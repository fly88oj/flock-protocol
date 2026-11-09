//! First-login trust anchors (docs/design.md §1.3.3(f) / §3.8, P0-5).
//!
//! Pinning model (finalized in the third review round, option 2): the
//! client anchors the **cluster root public key** and holds the
//! root-signed [`ClusterDirectory`] (the full set of [`ServerEntry`] =
//! the public part of the join credentials; the endpoint list and the
//! entries are covered by **one and the same signature**, preventing
//! "true list, fake entries" splicing). Any endpoint gives 1-RTT (I1's
//! ML-KEM ct is encapsulated to that endpoint ServerEntry's static
//! hybrid public key); rotating one server's key = a root-signed new
//! directory (dir_version increments) + a client dir_pull refresh;
//! switching endpoints or adding servers **never produces I0**.
//!
//! - [`PinStore`]: pinning granularity = `cluster_id → cluster root
//!   public key` (known_hosts semantics, cluster-root level;
//!   server-level material is not separately TOFU'd — it is endorsed by
//!   the root signature). A root public key change = a
//!   [`PinVerdict::Mismatch`] (carrying both the old and new keys,
//!   explicitly surfacing the data source, **must not be silently
//!   skipped**). The file adapter ships first
//!   ([`PinStore::save`]/[`PinStore::load`], 0600 on unix); a keystore
//!   adapter for mobile follows (seam).
//! - [`InviteFile`] v3: a root-signed ClusterDirectory with the full
//!   server material + a one-time invite_id + expiry (default 7 days,
//!   §2.4). **v1 fingerprint-only and v2 single-server-material invites
//!   are no longer accepted** — under a multi-server cluster they cannot
//!   support 1-RTT to any endpoint (§3.8). The invite_id single-use
//!   semantics are guaranteed by this repository's sync crate's Raft
//!   state machine (redeem_invite dedup, §4); this module does only
//!   structural validation.
//! - [`ClusterDirectory`]: dir_version monotonically increasing;
//!   `PinStore::record_directory` is the landing path for dir_pull
//!   refreshes (root-signature verification + pin comparison + version
//!   rollback rejection).
//!
//! # Residual-risk statement (must not be silent, §1.3.3f/§2.5-3)
//!
//! **TOFU does not defend against an online MITM at first login**: on
//! first connect an attacker can self-sign a whole "root public key +
//! credential chain", and the client pins the attacker's root (the same
//! class of limitation as SSH known_hosts; verdict §3.9 — the attack is
//! only partially closed). Organizational settings must go through the
//! strong invite-file path; the TOFU first-connect root-fingerprint
//! confirmation UI must not be silent.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

// Access-material types already defined by the session layer (one
// credential, two uses: server mutual-recognition §4 / client access
// material, §1.3.3f) and the shared parse cursor Rd (ponytail: removes
// the copies that used to duplicate session's, field for field)
pub use crate::session::{
    fingerprint_ed25519, sign_server_entry, verify_server_entry, ClusterId, ServerEntry, ServerId,
    ServerPin,
};
use crate::session::{Rd, RdErr};

/// Invite file version (v3; v1/v2 rejected).
pub const INVITE_VERSION: u8 = 3;
/// Directory structure version.
pub const DIRECTORY_VERSION: u8 = 1;
/// Invite default validity: 7 days (§1.3.3f "default 7 days
/// (configurable)").
pub const INVITE_DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;

const SIG_DIRECTORY: &[u8] = b"flock-protocol/trust/cluster-directory/v1";
const SIG_INVITE: &[u8] = b"flock-protocol/trust/invite/v3";

/// Trust-layer error.
#[derive(Debug)]
pub enum TrustError {
    /// Underlying IO.
    Io(io::Error),
    /// Root signature verification failed (root signature mismatch /
    /// entries tampered / bytes corrupted).
    BadSignature,
    /// Unsupported invite file version (v1/v2 rejected; the byte is the
    /// in-file version).
    UnsupportedInviteVersion(u8),
    /// Invite expired.
    Expired { now_unix: u64, expiry_unix: u64 },
    /// Cluster root public key changed (explicit alert path: carries the
    /// pinned value and the presented value; must not be silent). Both
    /// keys boxed (Err payload size discipline; contents are public keys,
    /// heap allocation carries no sensitive surface).
    RootChanged {
        cluster_id: ClusterId,
        pinned: Box<VerifyingKey>,
        presented: Box<VerifyingKey>,
    },
    /// Directory version rollback (dir_version must increase
    /// monotonically; stored = the previously seen version, got = this
    /// version).
    DirVersionRollback { stored: u64, got: u64 },
    /// Encoding violation (lengths/missing fields/trailing bytes).
    Encoding(&'static str),
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::Io(e) => write!(f, "trust: io: {e}"),
            TrustError::BadSignature => write!(f, "trust: root signature mismatch"),
            TrustError::UnsupportedInviteVersion(v) => {
                write!(f, "trust: invite version {v} unsupported (v3 only)")
            }
            TrustError::Expired {
                now_unix,
                expiry_unix,
            } => {
                write!(
                    f,
                    "trust: invite expired (now={now_unix}, expiry={expiry_unix})"
                )
            }
            TrustError::RootChanged { cluster_id, .. } => {
                write!(f, "trust: cluster root key changed for {cluster_id:?} (explicit re-confirmation required)")
            }
            TrustError::DirVersionRollback { stored, got } => {
                write!(
                    f,
                    "trust: directory version rollback (stored={stored}, got={got})"
                )
            }
            TrustError::Encoding(s) => write!(f, "trust: encoding: {s}"),
        }
    }
}
impl std::error::Error for TrustError {}
impl From<RdErr> for TrustError {
    fn from(e: RdErr) -> Self {
        TrustError::Encoding(e.0)
    }
}
impl From<io::Error> for TrustError {
    fn from(e: io::Error) -> Self {
        TrustError::Io(e)
    }
}

// ============================================================================
// ClusterDirectory (root-signed directory: endpoint list and entries
// co-signed, §1.3.3f option 2)
// ============================================================================

/// Root-signed cluster directory: the full server access material +
/// monotonically increasing dir_version.
///
/// The signature covers `cluster_id ‖ dir_version ‖ server count ‖ all
/// ServerEntry fields` — "true list, fake entries" splicing fails at
/// verification.
#[derive(Debug, Clone)]
pub struct ClusterDirectory {
    /// Owning cluster.
    pub cluster_id: ClusterId,
    /// Increasing version (one server rotating keys ⇒ a root-signed new
    /// directory ⇒ client dir_pull refresh; rollbacks rejected).
    pub dir_version: u64,
    /// The full server access material.
    pub servers: Vec<ServerEntry>,
    /// The root key's signature over canonical_bytes.
    pub root_sig: Signature,
}

/// ServerEntry field encoding (without the domain-separation label; for
/// embedding inside directories/invites).
fn entry_fields(e: &ServerEntry, out: &mut Vec<u8>) {
    out.extend_from_slice(&e.server_id.0);
    out.extend_from_slice(&(e.relay_endpoint.len() as u16).to_le_bytes());
    out.extend_from_slice(e.relay_endpoint.as_bytes());
    out.extend_from_slice(e.identity_pub.as_bytes());
    out.extend_from_slice(&e.static_hybrid_pub.to_bytes());
}

impl ClusterDirectory {
    /// Canonical bytes covered by the signature (excluding root_sig
    /// itself).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIG_DIRECTORY.len() + 24 + self.servers.len() * 1300);
        v.extend_from_slice(SIG_DIRECTORY);
        v.extend_from_slice(&self.cluster_id.0);
        v.extend_from_slice(&self.dir_version.to_le_bytes());
        v.extend_from_slice(&(self.servers.len() as u16).to_le_bytes());
        for e in &self.servers {
            entry_fields(e, &mut v);
        }
        v
    }

    /// Issue with the root key (ops/test assembly path; the root key is
    /// kept offline, §4).
    pub fn issue(
        root: &SigningKey,
        cluster_id: ClusterId,
        dir_version: u64,
        servers: Vec<ServerEntry>,
    ) -> Self {
        let mut dir = ClusterDirectory {
            cluster_id,
            dir_version,
            servers,
            root_sig: Signature::from_bytes(&[0; 64]),
        };
        dir.root_sig = root.sign(&dir.canonical_bytes());
        dir
    }

    /// Verify with the root public key (entries tampered ⇒ fails; root
    /// swapped ⇒ fails).
    pub fn verify(&self, root_pub: &VerifyingKey) -> bool {
        root_pub
            .verify(&self.canonical_bytes(), &self.root_sig)
            .is_ok()
    }

    /// Look up endpoint material by server_id.
    pub fn find(&self, server_id: &ServerId) -> Option<&ServerEntry> {
        self.servers.iter().find(|e| &e.server_id == server_id)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(DIRECTORY_VERSION);
        out.extend_from_slice(&self.cluster_id.0);
        out.extend_from_slice(&self.dir_version.to_le_bytes());
        out.extend_from_slice(&(self.servers.len() as u16).to_le_bytes());
        for e in &self.servers {
            entry_fields(e, out);
        }
        out.extend_from_slice(&self.root_sig.to_bytes());
    }

    /// Serialize (the dir_pull delivery wire format, §3.8/§3.11;
    /// `[ver][cluster][dir_version][n]{entries}[root_sig]`). Isomorphic
    /// with the embedded directory segment of `InviteFile::to_bytes`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(17 + self.servers.len() * 1300);
        self.encode(&mut v);
        v
    }

    /// Deserialize (structural; root-signature verification goes through
    /// [`ClusterDirectory::verify`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        let mut rd = Rd::new(bytes);
        let dir = Self::decode(&mut rd)?;
        if !rd.done() {
            return Err(TrustError::Encoding("trailing bytes"));
        }
        Ok(dir)
    }

    fn decode(rd: &mut Rd<'_>) -> Result<Self, TrustError> {
        let ver = rd.u8()?;
        if ver != DIRECTORY_VERSION {
            return Err(TrustError::Encoding("directory version"));
        }
        let cluster_id = ClusterId(rd.arr16()?);
        let dir_version = rd.u64()?;
        let n = rd.u16()? as usize;
        if n > 4096 {
            return Err(TrustError::Encoding("directory too large"));
        }
        let mut servers = Vec::with_capacity(n);
        for _ in 0..n {
            let server_id = ServerId(rd.arr16()?);
            let ep_len = rd.u16()? as usize;
            if ep_len > 512 {
                return Err(TrustError::Encoding("endpoint too long"));
            }
            let endpoint = String::from_utf8(rd.take(ep_len)?.to_vec())
                .map_err(|_| TrustError::Encoding("endpoint encoding"))?;
            let identity_pub = VerifyingKey::from_bytes(&rd.arr32()?)
                .map_err(|_| TrustError::Encoding("identity pubkey"))?;
            let mut hybrid = [0u8; crate::kem::HYBRID_PUB_LEN];
            hybrid.copy_from_slice(rd.take(crate::kem::HYBRID_PUB_LEN)?);
            let static_hybrid_pub = crate::kem::HybridPubkey::from_bytes(&hybrid)
                .map_err(|_| TrustError::Encoding("static hybrid pubkey"))?;
            servers.push(ServerEntry {
                server_id,
                relay_endpoint: endpoint,
                identity_pub,
                static_hybrid_pub,
            });
        }
        let sig_arr = rd.arr64()?;
        let root_sig = Signature::from_bytes(&sig_arr);
        Ok(ClusterDirectory {
            cluster_id,
            dir_version,
            servers,
            root_sig,
        })
    }
}

// ============================================================================
// InviteFile v3
// ============================================================================

/// Invite file v3 (§1.3.3f): a root-signed ClusterDirectory with the
/// full server material + one-time invite_id + expiry. An invited client
/// gets 1-RTT directly to any endpoint (including after switches/
/// migrations), fully avoiding TOFU.
#[derive(Debug, Clone)]
pub struct InviteFile {
    /// The root-signed cluster directory.
    pub directory: ClusterDirectory,
    /// Cluster root public key (the trust anchor itself; paired with the
    /// issuing root).
    pub cluster_root_pub: VerifyingKey,
    /// Expiry instant (unix seconds; default issue + 7 days).
    pub expiry_unix: u64,
    /// One-time consumption credential identifier (deduplicated in the
    /// Raft state machine; structural validation only inside this
    /// library).
    pub invite_id: [u8; 16],
    /// Root-key signature covering the directory canonical bytes ‖
    /// root_pub ‖ expiry ‖ invite_id.
    pub root_sig: Signature,
}

/// Current unix seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl InviteFile {
    /// Issue with the root key (expiry recommended now +
    /// [`INVITE_DEFAULT_TTL_SECS`]).
    pub fn issue(
        root: &SigningKey,
        cluster_id: ClusterId,
        dir_version: u64,
        servers: Vec<ServerEntry>,
        expiry_unix: u64,
        invite_id: [u8; 16],
    ) -> Self {
        let directory = ClusterDirectory::issue(root, cluster_id, dir_version, servers);
        let mut inv = InviteFile {
            directory,
            cluster_root_pub: root.verifying_key(),
            expiry_unix,
            invite_id,
            root_sig: Signature::from_bytes(&[0; 64]),
        };
        inv.root_sig = root.sign(&inv.canonical_bytes());
        inv
    }

    /// Canonical bytes covered by the signature (excluding root_sig
    /// itself).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = self.directory.canonical_bytes();
        v.extend_from_slice(SIG_INVITE);
        v.extend_from_slice(self.cluster_root_pub.as_bytes());
        v.extend_from_slice(&self.expiry_unix.to_le_bytes());
        v.extend_from_slice(&self.invite_id);
        v
    }

    /// Structural self-consistency verification (root_sig over
    /// canonical_bytes; any field tampered ⇒ fails). Anti-impersonation
    /// (root substitution) requires the caller to compare against the
    /// pinned/displayed root fingerprint — see
    /// [`InviteFile::verify_against`].
    pub fn verify(&self) -> bool {
        self.cluster_root_pub
            .verify(&self.canonical_bytes(), &self.root_sig)
            .is_ok()
            && self.directory.verify(&self.cluster_root_pub)
    }

    /// Verify against an externally known root public key (pinned / an
    /// administrator-distributed root).
    pub fn verify_against(&self, known_root: &VerifyingKey) -> bool {
        self.cluster_root_pub == *known_root && self.verify()
    }

    /// Version/expiry check (now is injected by the caller, keeping it
    /// testable).
    pub fn check(&self, now_unix: u64) -> Result<(), TrustError> {
        if self.expiry_unix <= now_unix {
            return Err(TrustError::Expired {
                now_unix,
                expiry_unix: self.expiry_unix,
            });
        }
        Ok(())
    }

    /// Serialize (invite files are managed as one-time credentials: 0600
    /// persistence is handled by [`save_invite`]).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64 + self.directory.servers.len() * 1300);
        v.push(INVITE_VERSION);
        self.directory.encode(&mut v);
        v.extend_from_slice(self.cluster_root_pub.as_bytes());
        v.extend_from_slice(&self.expiry_unix.to_le_bytes());
        v.extend_from_slice(&self.invite_id);
        v.extend_from_slice(&self.root_sig.to_bytes());
        v
    }

    /// Deserialize (including the v3 version check and structural
    /// self-consistency verification: root signature mismatch / entries
    /// tampered ⇒ rejected).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        let mut rd = Rd::new(bytes);
        let ver = rd.u8()?;
        if ver != INVITE_VERSION {
            return Err(TrustError::UnsupportedInviteVersion(ver));
        }
        let directory = ClusterDirectory::decode(&mut rd)?;
        let cluster_root_pub = VerifyingKey::from_bytes(&rd.arr32()?)
            .map_err(|_| TrustError::Encoding("root pubkey"))?;
        let expiry_unix = rd.u64()?;
        let invite_id = rd.arr16()?;
        let sig_arr = rd.arr64()?;
        let root_sig = Signature::from_bytes(&sig_arr);
        if !rd.done() {
            return Err(TrustError::Encoding("trailing bytes"));
        }
        let inv = InviteFile {
            directory,
            cluster_root_pub,
            expiry_unix,
            invite_id,
            root_sig,
        };
        if !inv.verify() {
            return Err(TrustError::BadSignature);
        }
        Ok(inv)
    }
}

/// 0600 persistence for credential-class files (same posture as
/// compat::write_private): on unix, **created** via
/// `OpenOptions::mode(0o600)` — the file is 0600 from birth, with no
/// "write first, tighten later" permission window (between `fs::write`
/// and `set_permissions` there is an overly permissive window). When
/// overwriting an existing file's overly permissive old permissions,
/// they are tightened afterwards. Native Windows has no POSIX permission
/// bits and falls back to an ordinary write.
fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()?;
        // Tighten possibly overly permissive old permissions of an
        // existing file (the creation path itself has no window).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Save an invite file (0600 on unix — managed as a one-time credential,
/// §1.3.3f invite lifetime).
pub fn save_invite(path: &Path, invite: &InviteFile) -> Result<(), TrustError> {
    write_private_file(path, &invite.to_bytes())?;
    Ok(())
}

/// Load an invite file (§1.3.3f `load_invite(path)`: disk read + v3
/// version check + structural verification; expiry/external-root
/// comparison are performed by the caller with context via
/// [`InviteFile::check`]/[`InviteFile::verify_against`]).
pub fn load_invite(path: &Path) -> Result<InviteFile, TrustError> {
    let bytes = std::fs::read(path)?;
    InviteFile::from_bytes(&bytes)
}

// ============================================================================
// PinStore (cluster_id → cluster root public key)
// ============================================================================

/// Pin verdict. Mismatch carries both keys (16+32+32B; verdict enums are
/// returned by value, an acceptable size — boxing would instead make the
/// most common Match path pay a heap allocation).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum PinVerdict {
    /// Presented root matches the pin.
    Match,
    /// Cluster root public key **changed** — explicit alert path:
    /// carries the pinned value and the presented value; a root key
    /// change = explicit alert + manual confirmation (§2.4 table); after
    /// confirmation, overwrite via [`PinStore::pin`].
    Mismatch {
        pinned: VerifyingKey,
        presented: VerifyingKey,
    },
    /// No pin for this cluster yet (TOFU first-connect path: display the
    /// [`Fingerprint`], then [`PinStore::pin`]).
    NotPinned,
}

/// Pin storage (known_hosts semantics, cluster-root level; the file
/// adapter ships first).
#[derive(Debug, Clone, Default)]
pub struct PinStore {
    pins: BTreeMap<[u8; 16], VerifyingKey>,
    /// Highest dir_version seen per cluster (dir_pull rollback
    /// detection).
    dir_versions: BTreeMap<[u8; 16], u64>,
}

impl PinStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// First pin (after TOFU confirmation) or overwrite (after a root
    /// change passes manual confirmation). Returns the verdict from
    /// before the write (NotPinned = first pin; Mismatch =
    /// change-overwrite — the caller must have gone through the alert
    /// flow).
    pub fn pin(&mut self, cluster_id: &ClusterId, root_pub: &VerifyingKey) -> PinVerdict {
        let prev = self.verify_pinned(cluster_id, root_pub);
        self.pins.insert(cluster_id.0, *root_pub);
        prev
    }

    /// Compare against the pin (no write). **A change must not be
    /// silent**: Mismatch must trigger the explicit alert UI (§3.8).
    pub fn verify_pinned(&self, cluster_id: &ClusterId, root_pub: &VerifyingKey) -> PinVerdict {
        match self.pins.get(&cluster_id.0) {
            Some(pinned) if pinned == root_pub => PinVerdict::Match,
            Some(pinned) => PinVerdict::Mismatch {
                pinned: *pinned,
                presented: *root_pub,
            },
            None => PinVerdict::NotPinned,
        }
    }

    /// Get a cluster's pinned root public key.
    pub fn pinned_root(&self, cluster_id: &ClusterId) -> Option<&VerifyingKey> {
        self.pins.get(&cluster_id.0)
    }

    /// Highest dir_version seen.
    pub fn seen_dir_version(&self, cluster_id: &ClusterId) -> Option<u64> {
        self.dir_versions.get(&cluster_id.0).copied()
    }

    /// dir_pull refresh landing (§3.8): root-signature verification →
    /// pin comparison (change ⇒ [`TrustError::RootChanged`] explicit
    /// alert path) → dir_version rollback rejection → record the
    /// version. Same-version redistribution (an idempotent replay of
    /// identical content) is allowed through.
    pub fn record_directory(
        &mut self,
        root_pub: &VerifyingKey,
        dir: &ClusterDirectory,
    ) -> Result<(), TrustError> {
        if !dir.verify(root_pub) {
            return Err(TrustError::BadSignature);
        }
        match self.verify_pinned(&dir.cluster_id, root_pub) {
            PinVerdict::Match => {}
            PinVerdict::Mismatch { pinned, presented } => {
                return Err(TrustError::RootChanged {
                    cluster_id: dir.cluster_id,
                    pinned: Box::new(pinned),
                    presented: Box::new(presented),
                })
            }
            PinVerdict::NotPinned => { /* first sight of the directory: the invite/TOFU path pins first */
            }
        }
        if let Some(&stored) = self.dir_versions.get(&dir.cluster_id.0) {
            if dir.dir_version < stored {
                return Err(TrustError::DirVersionRollback {
                    stored,
                    got: dir.dir_version,
                });
            }
        }
        self.dir_versions.insert(dir.cluster_id.0, dir.dir_version);
        Ok(())
    }

    /// Serialize (format: `[ver=1][count u16]{ [16 cluster][32 root][8
    /// dir_version] }`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&(self.pins.len() as u16).to_le_bytes());
        for (id, root) in &self.pins {
            v.extend_from_slice(id);
            v.extend_from_slice(root.as_bytes());
            v.extend_from_slice(
                &self
                    .dir_versions
                    .get(id)
                    .copied()
                    .unwrap_or(0)
                    .to_le_bytes(),
            );
        }
        v
    }

    /// Deserialize.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        let mut rd = Rd::new(bytes);
        let ver = rd.u8()?;
        if ver != 1 {
            return Err(TrustError::Encoding("pinstore version"));
        }
        let n = rd.u16()? as usize;
        let mut pins = BTreeMap::new();
        let mut dir_versions = BTreeMap::new();
        for _ in 0..n {
            let id = rd.arr16()?;
            let root = VerifyingKey::from_bytes(&rd.arr32()?)
                .map_err(|_| TrustError::Encoding("pin root pubkey"))?;
            let dv = rd.u64()?;
            pins.insert(id, root);
            if dv > 0 {
                dir_versions.insert(id, dv);
            }
        }
        if !rd.done() {
            return Err(TrustError::Encoding("trailing bytes"));
        }
        Ok(PinStore { pins, dir_versions })
    }

    /// Persist (unix 0600 — pin files are treated as credentials;
    /// created as 0600 directly, no "write first, tighten later" window,
    /// see [`write_private_file`]).
    pub fn save(&self, path: &Path) -> Result<(), TrustStoreError> {
        write_private_file(path, &self.to_bytes())?;
        Ok(())
    }

    /// Load from disk.
    pub fn load(path: &Path) -> Result<Self, TrustStoreError> {
        let bytes = std::fs::read(path)?;
        Ok(PinStore::from_bytes(&bytes)?)
    }
}

/// PinStore persistence error (IO or encoding).
#[derive(Debug)]
pub struct TrustStoreError(TrustError);

impl std::fmt::Display for TrustStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "trust: pin store: {}", self.0)
    }
}
impl std::error::Error for TrustStoreError {}
impl From<io::Error> for TrustStoreError {
    fn from(e: io::Error) -> Self {
        TrustStoreError(TrustError::Io(e))
    }
}
impl From<TrustError> for TrustStoreError {
    fn from(e: TrustError) -> Self {
        TrustStoreError(e)
    }
}

// ============================================================================
// Session-side landing of TOFU → pinning
// ============================================================================

/// TOFU bootstrap confirmation + pin landing (§1.3.3c/§1.3.3f closed
/// loop):
/// 1. `verify_pinned`: NotPinned ⇒ `pin` (first pin; the caller has
///    already displayed the root fingerprint and confirmed); Mismatch ⇒
///    [`TrustError::RootChanged`] (**alert path, not silent**).
/// 2. On success, run [`crate::session::TofuBootstrap::confirm`] to
///    finish I1/R1.
pub async fn confirm_tofu_and_pin<S>(
    boot: crate::session::TofuBootstrap<S>,
    pins: &mut PinStore,
) -> Result<crate::session::Tunnel, TrustTofuError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let cluster_id = boot.cluster_id();
    let root = *boot.root_pub();
    match pins.verify_pinned(&cluster_id, &root) {
        PinVerdict::Match => {}
        PinVerdict::NotPinned => {
            pins.pin(&cluster_id, &root);
        }
        PinVerdict::Mismatch { pinned, presented } => {
            return Err(TrustTofuError(TrustError::RootChanged {
                cluster_id,
                pinned: Box::new(pinned),
                presented: Box::new(presented),
            }))
        }
    }
    let tunnel = boot
        .confirm()
        .await
        .map_err(|e| TrustTofuError(TrustError::Io(io::Error::other(format!("{e}")))))?;
    Ok(tunnel)
}

/// TOFU confirmation error (trust layer or handshake layer).
#[derive(Debug)]
pub struct TrustTofuError(TrustError);

impl std::fmt::Display for TrustTofuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "trust: tofu confirm: {}", self.0)
    }
}
impl std::error::Error for TrustTofuError {}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8) -> ServerEntry {
        let identity = SigningKey::from_bytes(&[n; 32]);
        let hybrid = crate::kem::HybridKeypair::generate(&mut crate::rand::rngs::OsRng);
        ServerEntry {
            server_id: ServerId([n; 16]),
            relay_endpoint: format!("relay-{n}.example:2300{n}"),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: hybrid.public(),
        }
    }

    fn fixture() -> (SigningKey, ClusterId) {
        (
            SigningKey::from_bytes(&crate::rand::random::<[u8; 32]>()),
            ClusterId([7; 16]),
        )
    }

    #[test]
    fn directory_tamper_detected() {
        let (root, cid) = fixture();
        let mut dir = ClusterDirectory::issue(&root, cid, 3, vec![entry(1), entry(2)]);
        assert!(
            dir.verify(&root.verifying_key()),
            "a legitimate directory passes"
        );
        // to_bytes/from_bytes round trip (the dir_pull wire format, §3.11)
        let back = ClusterDirectory::from_bytes(&dir.to_bytes()).expect("dir roundtrip");
        assert_eq!(back.dir_version, dir.dir_version);
        assert!(back.verify(&root.verifying_key()));
        let mut trailing = dir.to_bytes();
        trailing.push(0);
        assert!(
            ClusterDirectory::from_bytes(&trailing).is_err(),
            "trailing bytes ⇒ rejected"
        );
        // An entry tampered (relay_endpoint swapped) ⇒ verification fails
        dir.servers[0].relay_endpoint = "evil.example:9".into();
        assert!(
            !dir.verify(&root.verifying_key()),
            "an entry tampered ⇒ rejected"
        );
        // Root swapped ⇒ verification fails
        let dir2 = ClusterDirectory::issue(&root, cid, 4, vec![entry(1)]);
        let other = SigningKey::from_bytes(&[9; 32]);
        assert!(
            !dir2.verify(&other.verifying_key()),
            "another root ⇒ rejected"
        );
        // dir_version altered ⇒ verification fails (the version is inside
        // the signature coverage)
        let mut dir3 = ClusterDirectory::issue(&root, cid, 3, vec![entry(1)]);
        dir3.dir_version = 99;
        assert!(
            !dir3.verify(&root.verifying_key()),
            "version tampering ⇒ rejected"
        );
    }

    #[test]
    fn invite_roundtrip_and_version_gate() {
        let (root, cid) = fixture();
        let inv = InviteFile::issue(
            &root,
            cid,
            1,
            vec![entry(1), entry(2)],
            now_unix() + 3600,
            [5; 16],
        );
        let bytes = inv.to_bytes();
        let back = InviteFile::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(back.invite_id, [5; 16]);
        assert!(back.verify());
        assert!(back.verify_against(&root.verifying_key()));
        // Root signature mismatch: tamper any covered field (invite_id)
        let mut tampered = bytes.clone();
        let id_off = bytes.len() - 64 - 16; // invite_id sits 16B before root_sig
        tampered[id_off] ^= 0x01;
        assert!(
            matches!(
                InviteFile::from_bytes(&tampered).unwrap_err(),
                TrustError::BadSignature
            ),
            "root signature mismatch ⇒ load rejected"
        );
        // v2 rejected
        let mut v2 = bytes;
        v2[0] = 2;
        assert!(matches!(
            InviteFile::from_bytes(&v2).unwrap_err(),
            TrustError::UnsupportedInviteVersion(2)
        ));
        // Expired
        let expired = InviteFile::issue(&root, cid, 1, vec![], 100, [5; 16]);
        assert!(matches!(
            expired.check(200).unwrap_err(),
            TrustError::Expired {
                now_unix: 200,
                expiry_unix: 100
            }
        ));
    }

    #[test]
    fn pinstore_verdicts_and_persistence() {
        let (root, cid) = fixture();
        let other = SigningKey::from_bytes(&[3; 32]);
        let mut pins = PinStore::new();
        assert_eq!(
            pins.verify_pinned(&cid, &root.verifying_key()),
            PinVerdict::NotPinned
        );
        // First pin
        let prev = pins.pin(&cid, &root.verifying_key());
        assert_eq!(prev, PinVerdict::NotPinned);
        assert_eq!(
            pins.verify_pinned(&cid, &root.verifying_key()),
            PinVerdict::Match
        );
        // Change-alert path (testable): Mismatch carries both keys, old
        // and new
        match pins.verify_pinned(&cid, &other.verifying_key()) {
            PinVerdict::Mismatch { pinned, presented } => {
                assert_eq!(pinned, root.verifying_key());
                assert_eq!(presented, other.verifying_key());
            }
            v => panic!("expected Mismatch, got {v:?}"),
        }
        // Serialization round trip
        let bytes = pins.to_bytes();
        let back = PinStore::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(
            back.verify_pinned(&cid, &root.verifying_key()),
            PinVerdict::Match
        );
    }

    // Persistence shapes: save_invite / PinStore::save round trips + 0600
    // on unix (created as 0600, no permission window from "fs::write
    // then tighten later" — this test also guards "readable back after
    // write" against regressions).
    #[test]
    fn invite_and_pinstore_save_roundtrip_and_mode() {
        let (root, cid) = fixture();
        let inv = InviteFile::issue(&root, cid, 1, vec![entry(1)], now_unix() + 3600, [6; 16]);
        let dir = std::env::temp_dir().join(format!("flock-trust-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ipath = dir.join("invite.bin");
        save_invite(&ipath, &inv).unwrap();
        assert_eq!(
            load_invite(&ipath).unwrap().invite_id,
            [6; 16],
            "the persisted invite reads back"
        );

        let mut pins = PinStore::new();
        pins.pin(&cid, &root.verifying_key());
        let ppath = dir.join("pins.bin");
        pins.save(&ppath).unwrap();
        assert_eq!(
            PinStore::load(&ppath)
                .unwrap()
                .verify_pinned(&cid, &root.verifying_key()),
            PinVerdict::Match,
            "the persisted pins read back"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&ipath).unwrap().permissions().mode() & 0o777,
                0o600,
                "invite 0600"
            );
            assert_eq!(
                std::fs::metadata(&ppath).unwrap().permissions().mode() & 0o777,
                0o600,
                "pins 0600"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_directory_rollback_rejected() {
        let (root, cid) = fixture();
        let mut pins = PinStore::new();
        pins.pin(&cid, &root.verifying_key());
        let v3 = ClusterDirectory::issue(&root, cid, 3, vec![entry(1)]);
        pins.record_directory(&root.verifying_key(), &v3)
            .expect("v3 accepted");
        assert_eq!(pins.seen_dir_version(&cid), Some(3));
        // Rollback to v2 ⇒ rejected
        let v2 = ClusterDirectory::issue(&root, cid, 2, vec![entry(1)]);
        assert!(
            matches!(
                pins.record_directory(&root.verifying_key(), &v2)
                    .unwrap_err(),
                TrustError::DirVersionRollback { stored: 3, got: 2 }
            ),
            "dir_version rollback ⇒ load rejected"
        );
        // v4 ⇒ accepted
        let v4 = ClusterDirectory::issue(&root, cid, 4, vec![entry(1), entry(2)]);
        pins.record_directory(&root.verifying_key(), &v4)
            .expect("v4 accepted");
        assert_eq!(pins.seen_dir_version(&cid), Some(4));
        // Issued under a swapped root ⇒ alert-path error
        let bad_root = SigningKey::from_bytes(&[9; 32]);
        let forged = ClusterDirectory::issue(&bad_root, cid, 5, vec![entry(1)]);
        assert!(
            matches!(
                pins.record_directory(&bad_root.verifying_key(), &forged)
                    .unwrap_err(),
                TrustError::RootChanged { .. }
            ),
            "root change ⇒ explicit alert path"
        );
    }
}
