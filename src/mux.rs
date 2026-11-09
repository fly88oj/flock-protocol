//! Multiplexing and EOF semantics (docs/design.md §1.3.3d / §3.6, P1-9,
//! VPN-14/16 protocol side).
//!
//! - The multiplexer = **rust-yamux 0.14.1** (the hashicorp-spec
//!   implementation; selection basis vpn-mesh §4.1/S29/S30), running
//!   **inside** the session record-layer encryption — stream counts/stream
//!   metadata are invisible to the relay. Link order:
//!   `TCP → record layer (counter-nonce AEAD) → yamux → logical streams`.
//! - **TCP half-close is forbidden** (frp T3 proved SHUT_WR tears down the
//!   whole chain, frp-compat §1.5): unidirectional finish is always a
//!   yamux FIN — i.e. [`Stream::finish`]; this wrapper type deliberately
//!   does **not** implement the `poll_shutdown` half-close path (the
//!   underlying yamux `poll_close` semantics = send FIN, called only
//!   inside `finish()`).
//! - **Heartbeats (implementation note for §1.3.3d "keepalive = yamux ping
//!   10s", stated honestly)**: yamux 0.14.1's public API exposes only
//!   `Connection::poll_*` and **no ping initiation** (`on_ping` only
//!   answers inbound pings; the old `Control::set_keep_alive_interval`
//!   was removed in the 0.14 API refactor — verified this round against
//!   the yamux-0.14.1/src/lib.rs Config fields and connection.rs). Hence
//!   the 10s heartbeat is carried by encrypted PING/PONG frames on the
//!   session record layer (crypto-2026 §6.4's originally recommended
//!   shape: keepalive frames are themselves encrypted frames), doubling
//!   as a relay liveness probe; if the peer's yamux pings proactively,
//!   this side's yamux still answers automatically per the spec.
//! - **Priorities (stated honestly)**: yamux 0.14.1 has no inter-stream
//!   scheduling priority interface (frame sends enqueue directly inside
//!   `Stream::poll_write`, no reordering hook). M1's "control streams
//!   high priority" lands in the session record layer — session control
//!   records (REKEY/PING/PONG) take a dedicated high-priority channel and
//!   go out before all stream data (session::write_pump biased select);
//!   [`Prio`] is a stream-level reserved slot — recorded, never reordered.
//! - [`PacketChannel`]: TUN-packet framing `[u16 len][ip packet]`
//!   (boundary-preserving), the library-side interface of VPN-14.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::io::{AsyncRead, AsyncWrite};
use futures::{ready, Stream as FStream, StreamExt as _};

/// Logical-stream priority tier (§3.6 `Prio` scheduling tier).
///
/// M1 semantics (see the module doc's "priorities" note):
/// [`Prio::Control`] streams register as control-purpose; session-level
/// control records (rekey/heartbeat) always go out before stream data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prio {
    /// Control-stream tier (signaling streams such as OPAQUE
    /// login/config delivery).
    Control,
    /// Ordinary data tier (default).
    Normal,
}

/// A logical stream over yamux (wrapping [`yamux::Stream`]; §3.6
/// interface: AsyncRead/Write + explicit finish).
///
/// EOF semantics: `finish()` = send a yamux FIN (unidirectional finish),
/// **never touching TCP half-close**; the peer observes EOF upon reading 0
/// bytes. Whole-stream close is handled by the session-layer teardown.
pub struct Stream {
    inner: yamux::Stream,
    prio: Prio,
}

impl Stream {
    pub(crate) fn new(inner: yamux::Stream, prio: Prio) -> Self {
        Stream { inner, prio }
    }

    /// Stream ID (yamux: client-opened streams are odd, server-opened
    /// even; the client's **first stream = 1**).
    ///
    /// For the assembly layer's stream dispatch (§3.12: first stream =
    /// control stream) — dispatching by ID is immune to yamux's lazy SYN
    /// (streams materialize only on first-frame data): a control stream
    /// silently held (id=1) never materializes, yet later materializing
    /// data streams (id>=3) are still correctly recognized as data-plane.
    pub fn id(&self) -> u32 {
        self.inner.id().val()
    }

    /// Take back the inner yamux stream (for the inbound parking fallback
    /// path; meaningless outside the library).
    pub(crate) fn into_inner(self) -> yamux::Stream {
        self.inner
    }

    /// This stream's priority tier.
    pub fn prio(&self) -> Prio {
        self.prio
    }

    /// Explicit unidirectional finish: send a yamux FIN (§1.3.3d forbids
    /// half-close — FIN is the only sanctioned path). Subsequent
    /// [`Stream::write_all`] returns an error; the peer's read side will
    /// observe EOF.
    pub async fn finish(&mut self) -> io::Result<()> {
        futures::AsyncWriteExt::close(&mut self.inner).await
    }

    /// Write all bytes (chunking ≤ the record-layer single-frame cap is
    /// handled inside MuxIo).
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        futures::AsyncWriteExt::write_all(&mut self.inner, buf).await
    }

    /// Read exactly `buf.len()` bytes; short reads after the peer's FIN
    /// give `UnexpectedEof`; a 0-length buf returns Ok immediately.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        futures::AsyncReadExt::read_exact(&mut self.inner, buf)
            .await
            .map(|_| ())
    }

    /// Read at most `buf.len()` bytes; `Ok(0)` = peer FIN (EOF).
    pub async fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        futures::AsyncReadExt::read(&mut self.inner, buf).await
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// **Not supported** (half-close forbidden: no implicit shutdown path
    /// is provided; unidirectional finish must be an explicit
    /// [`Stream::finish`]).
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mux: implicit shutdown disabled; use Stream::finish()",
        )))
    }
}

/// TUN packet channel (§1.3.6/§3.6 `PacketChannel`, the VPN-14
/// library-side interface).
///
/// Framing: `[u16 LE len][ip packet]` (packet-boundary preserving).
/// Single-packet cap 65535B (u16 length field); the deployment-form MTU
/// of 1280 (§2.1) is far below it.
pub struct PacketChannel {
    stream: Stream,
}

/// Single-packet length cap (u16 frame header).
pub const MAX_PACKET: usize = u16::MAX as usize;

/// Send one packet frame (`[u16 LE len][pkt]`; same wire format as
/// [`PacketChannel::send`]).
///
/// The free-function form serves "split read/write + dedicated-task"
/// assemblies — directly awaiting [`PacketChannel::recv`] inside a select
/// loop is **not cancellation-safe** (framing is two read_exacts: a
/// half-way future dropped ⇒ the already-consumed header/body bytes are
/// lost and the frame stream desynchronizes permanently). The write side
/// has no such issue: a full frame is awaited to completion inside the
/// branch body.
pub async fn send_packet<W>(w: &mut W, pkt: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use futures::AsyncWriteExt as _;
    if pkt.len() > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mux: packet exceeds u16 frame limit (65535B)",
        ));
    }
    let mut frame = Vec::with_capacity(2 + pkt.len());
    frame.extend_from_slice(&(pkt.len() as u16).to_le_bytes());
    frame.extend_from_slice(pkt);
    w.write_all(&frame).await
}

/// Receive one packet frame (peer FIN with no partial packet ⇒
/// `UnexpectedEof`).
///
/// Cancellation-safety note: internally this is still two read_exacts —
/// **loop it only inside a dedicated reader task** (the task is never
/// cancelled by select; half-way state lives safely on its own stack).
pub async fn recv_packet<R>(r: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    use futures::AsyncReadExt as _;
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_le_bytes(hdr) as usize;
    let mut pkt = vec![0u8; len];
    r.read_exact(&mut pkt).await?;
    Ok(pkt)
}

impl PacketChannel {
    /// Assembly constructor (shared by the outbound
    /// `Tunnel::open_packet_channel` and the accepting side's
    /// `accept_stream`; ponytail: merges the former new/from_stream dual
    /// constructors into one).
    pub fn from_stream(stream: Stream) -> Self {
        PacketChannel { stream }
    }

    /// Consume into the underlying stream (for test paths like chunked
    /// injection).
    pub fn into_stream(self) -> Stream {
        self.stream
    }

    /// Send one IP packet: `[u16 len][pkt]`.
    pub async fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        send_packet(&mut self.stream, pkt).await
    }

    /// Receive one IP packet. Peer FIN with no partial packet ⇒
    /// `UnexpectedEof`.
    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        recv_packet(&mut self.stream).await
    }

    /// Unidirectional finish (passes through [`Stream::finish`]'s yamux
    /// FIN semantics).
    pub async fn finish(&mut self) -> io::Result<()> {
        self.stream.finish().await
    }

    /// Consume into a packet-iterator stream (§3.6 `recv_stream()`):
    /// yields packet by packet; error/EOF terminates.
    pub fn recv_stream(self) -> PacketRx {
        PacketRx {
            framer: FrameRx::new(self.stream),
        }
    }
}

/// `[u16 LE len][pkt]` framing decode state machine (the kernel of
/// [`PacketRx`]).
///
/// The framing state (2B header + partial body buffer) lives in
/// **struct fields** — preserved across polls/wakeups. The generic is on
/// the reader surface `R`, so "packet body arriving across multiple
/// wakeups" can be regression-tested directly with a mock reader
/// ([`PacketChannel::recv`]/[`recv_packet`]'s two-read_exact form carries
/// no cross-call state; dropping a half-way future permanently
/// desynchronizes the frame stream — see the cancellation-safety note on
/// `send_packet`).
pub(crate) struct FrameRx<R> {
    r: R,
    hdr: [u8; 2],
    hdr_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
}

impl<R: AsyncRead + Unpin> FrameRx<R> {
    pub(crate) fn new(r: R) -> Self {
        FrameRx {
            r,
            hdr: [0; 2],
            hdr_filled: 0,
            body: Vec::new(),
            body_filled: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> FStream for FrameRx<R> {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // Frame header: fill incrementally in 2B (each poll_read advances
        // at most one stretch; Pending returns while keeping the bytes
        // already received).
        while this.hdr_filled < this.hdr.len() {
            match Pin::new(&mut this.r).poll_read(cx, &mut this.hdr[this.hdr_filled..]) {
                // EOF ⇒ follow recv_packet's read_exact→UnexpectedEof→None
                // semantics (including half-frame truncation).
                Poll::Ready(Ok(0)) => return Poll::Ready(None),
                Poll::Ready(Ok(n)) => this.hdr_filled += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
        if this.body.is_empty() && this.body_filled == 0 {
            let len = u16::from_le_bytes(this.hdr) as usize;
            this.body = vec![0u8; len];
        }
        while this.body_filled < this.body.len() {
            match Pin::new(&mut this.r).poll_read(cx, &mut this.body[this.body_filled..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(None),
                Poll::Ready(Ok(n)) => this.body_filled += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
        let pkt = std::mem::take(&mut this.body);
        this.body_filled = 0;
        this.hdr_filled = 0;
        Poll::Ready(Some(Ok(pkt)))
    }
}

/// The product of [`PacketChannel::recv_stream`]: a
/// `futures::Stream<Item = io::Result<Vec<u8>>>`.
///
/// Framing state is kept in [`FrameRx`] fields across polls — when a
/// packet body arrives across multiple wakeups, the body's first 2 bytes
/// are no longer misread as a new frame header (regression test
/// `packet_rx_frames_survive_split_arrival`).
pub struct PacketRx {
    framer: FrameRx<Stream>,
}

impl FStream for PacketRx {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().framer.poll_next_unpin(cx)
    }
}

// —— Yamux frame-carrier IO for session-internal assembly (plaintext
// pipes: the record layer has already encrypted/decrypted) ——

/// In-flight data-channel send future (tokio mpsc has no poll-style
/// reserve, hence the stored self-referential future).
type SendFut =
    Pin<Box<dyn Future<Output = Result<(), tokio::sync::mpsc::error::SendError<Vec<u8>>>> + Send>>;

/// Yamux carrier IO: the read end = decrypted DATA records delivered by
/// the read pump; the write end = payloads to be sealed, handed to the
/// write pump (sealing happens at the write pump's single serialization
/// point, guaranteeing record-counter order = actual wire order).
pub(crate) struct MuxIo {
    pub(crate) plain_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pub(crate) data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub(crate) rbuf: Vec<u8>,
    pub(crate) send_fut: Option<SendFut>,
    pub(crate) send_len: usize,
}

impl MuxIo {
    /// Assembly constructor (used by session::spawn_session).
    pub(crate) fn new(
        plain_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Self {
        MuxIo {
            plain_rx,
            data_tx,
            rbuf: Vec::new(),
            send_fut: None,
            send_len: 0,
        }
    }
}

impl AsyncRead for MuxIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.rbuf.is_empty() {
            match ready!(self.plain_rx.poll_recv(cx)) {
                Some(payload) => self.rbuf = payload,
                None => return Poll::Ready(Ok(0)), // session closed (peer
                                                   // EOF / local kill)
            }
        }
        let n = buf.len().min(self.rbuf.len());
        buf[..n].copy_from_slice(&self.rbuf[..n]);
        self.rbuf.drain(..n);
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for MuxIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Chunk cap: a single record payload ≤ 1MiB (§1.3.3c record-layer
        // invariant); 64KiB keeps record granularity fine without touching
        // the cap.
        if self.send_fut.is_none() {
            let n = buf.len().min(64 * 1024);
            self.send_len = n;
            // The async move block holds a cloned Sender ⇒ the future is
            // 'static (send borrows &self).
            let tx = self.data_tx.clone();
            let chunk = buf[..n].to_vec();
            self.send_fut = Some(Box::pin(async move { tx.send(chunk).await }));
        }
        let this = &mut *self;
        match this.send_fut.as_mut().expect("just set").as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                this.send_fut = None;
                Poll::Ready(Ok(this.send_len))
            }
            Poll::Ready(Err(_)) => {
                // A completed future must be cleared out of send_fut:
                // yamux retries poll_write after a write error, and
                // re-polling a completed future panics with "async fn
                // resumed after completion" (observed live when killing
                // the mux driver task and disturbing the session teardown
                // ordering — A9 dead-link detection was delayed).
                this.send_fut = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux: record writer gone",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // a full bounded channel is the backpressure;
                            // flush has no separate semantics
    }

    /// Half-close forbidden: no shutdown of any kind on the carrier IO
    /// (whole-chain teardown is the session layer's unified
    /// responsibility).
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prio_values() {
        assert_ne!(Prio::Control, Prio::Normal);
    }

    /// Trickle-arrival mock (deferred delivery): each poll_read pops one
    /// preset chunk (when the chunk exceeds the requested buf, the
    /// remainder is kept for the next read); an empty queue ⇒ Pending (a
    /// noop waker does not auto-rewake; the test polls again manually —
    /// precise control over the byte-slicing of "arrival across
    /// wakeups"); after `eof = true`, returns Ok(0) to simulate FIN.
    struct TrickleReader {
        chunks: std::collections::VecDeque<Vec<u8>>,
        eof: bool,
    }

    impl AsyncRead for TrickleReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            match self.chunks.pop_front() {
                Some(mut c) => {
                    let n = c.len().min(buf.len());
                    buf[..n].copy_from_slice(&c[..n]);
                    if n < c.len() {
                        c.drain(..n);
                        self.chunks.push_front(c);
                    }
                    Poll::Ready(Ok(n))
                }
                None if self.eof => Poll::Ready(Ok(0)),
                None => Poll::Pending,
            }
        }
    }

    /// Regression (review-confirmed defect): the old PacketRx rebuilt a
    /// `ch.recv()` future on every poll and dropped it on Pending — when a
    /// packet body arrived across wakeups, the consumed header/body state
    /// was lost, the body's first 2 bytes were treated as a new header,
    /// and the frame stream desynchronized permanently. With the framing
    /// state hoisted into FrameRx fields: byte-by-byte trickle arrival
    /// (one poll per byte, returning Pending multiple times in between)
    /// must frame completely.
    #[test]
    fn packet_rx_frames_survive_split_arrival() {
        use futures::task::noop_waker;
        use futures::StreamExt as _;

        let pkt1: Vec<u8> = (0..40u8).collect();
        let pkt2: Vec<u8> = vec![0xA5; 5];
        let pkt3: Vec<u8> = Vec::new(); // 0-length packet (legal frame: len=0)
        let mut wire: Vec<u8> = Vec::new();
        for p in [&pkt1, &pkt2, &pkt3] {
            wire.extend_from_slice(&(p.len() as u16).to_le_bytes());
            wire.extend_from_slice(p);
        }

        let reader = TrickleReader {
            chunks: std::collections::VecDeque::new(),
            eof: false,
        };
        let mut rx = FrameRx::new(reader);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut got: Vec<Vec<u8>> = Vec::new();
        for &b in &wire {
            // Deliver only 1 byte then poll: frame incomplete ⇒ Pending
            // (the old implementation's half-way future was dropped here,
            // and the next poll rebuilt a header from body bytes); frame
            // complete ⇒ Ready with a packet.
            rx.r.chunks.push_back(vec![b]);
            loop {
                match rx.poll_next_unpin(&mut cx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(p))) => got.push(p),
                    Poll::Ready(Some(Err(e))) => panic!("framing error on trickle arrival: {e}"),
                    Poll::Ready(None) => panic!("EOF before all data arrived"),
                }
            }
        }
        assert_eq!(
            got,
            vec![pkt1, pkt2, pkt3],
            "trickle arrival frames completely, packet by packet, byte by byte"
        );

        // All frames received ⇒ Pending (waiting for more data); FIN ⇒
        // None as the finish.
        assert!(rx.poll_next_unpin(&mut cx).is_pending());
        rx.r.eof = true;
        assert!(matches!(rx.poll_next_unpin(&mut cx), Poll::Ready(None)));
    }

    /// Second shape of the trickle-arrival regression: header/body
    /// arriving as coarse chunks across polls (header as one chunk, body
    /// in two halves, the next frame immediately following in the same
    /// chunk) — after each chunk delivery, poll until Pending; half-way
    /// state survives across polls.
    #[test]
    fn packet_rx_frames_survive_chunked_body_arrival() {
        use futures::task::noop_waker;
        use futures::StreamExt as _;

        let pkt1: Vec<u8> = (0..100u8).collect();
        let pkt2: Vec<u8> = vec![0x5A; 3];
        let frame1 = {
            let mut f = (pkt1.len() as u16).to_le_bytes().to_vec();
            f.extend_from_slice(&pkt1);
            f
        };
        let frame2 = {
            let mut f = (pkt2.len() as u16).to_le_bytes().to_vec();
            f.extend_from_slice(&pkt2);
            f
        };

        let reader = TrickleReader {
            chunks: std::collections::VecDeque::new(),
            eof: false,
        };
        let mut rx = FrameRx::new(reader);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut got: Vec<Vec<u8>> = Vec::new();
        let chunks = vec![
            frame1[..2].to_vec(),   // frame 1 header (body absent ⇒ Pending)
            frame1[2..52].to_vec(), // frame 1 body first half (mid-way ⇒ Pending)
            [frame1[52..].to_vec(), frame2].concat(), // frame 1 body second half + all of frame 2, same chunk
        ];
        for c in chunks {
            rx.r.chunks.push_back(c);
            loop {
                match rx.poll_next_unpin(&mut cx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(p))) => got.push(p),
                    Poll::Ready(Some(Err(e))) => panic!("framing error on chunked arrival: {e}"),
                    Poll::Ready(None) => panic!("EOF before all data arrived"),
                }
            }
        }
        assert_eq!(
            got,
            vec![pkt1, pkt2],
            "chunk-boundary framing survives across polls"
        );
        rx.r.eof = true;
        assert!(matches!(rx.poll_next_unpin(&mut cx), Poll::Ready(None)));
    }

    /// Red-shape control (proving the regression tests above have teeth):
    /// an implementation isomorphic to the pre-fix PacketRx — rebuilding a
    /// "two read_exact" recv future on every poll, dropped on Pending.
    /// Under the same trickle-arrival input it must desynchronize: a
    /// half-read header is dropped, and the next poll reassembles a wrong
    /// frame out of the body's first bytes as a header.
    struct OldFrameRx<R> {
        r: R,
    }

    impl<R: AsyncRead + Unpin> FStream for OldFrameRx<R> {
        type Item = io::Result<Vec<u8>>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let r = &mut self.get_mut().r;
            let mut fut = std::pin::pin!(async {
                let mut hdr = [0u8; 2];
                futures::AsyncReadExt::read_exact(r, &mut hdr).await?;
                let len = u16::from_le_bytes(hdr) as usize;
                let mut pkt = vec![0u8; len];
                futures::AsyncReadExt::read_exact(r, &mut pkt).await?;
                Ok::<_, io::Error>(pkt)
            });
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(pkt)) => Poll::Ready(Some(Ok(pkt))),
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    Poll::Ready(None)
                }
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    #[test]
    fn old_recreate_future_pattern_desyncs_on_split_arrival() {
        use futures::task::noop_waker;
        use futures::StreamExt as _;

        let pkt: Vec<u8> = (0..40u8).collect();
        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&(pkt.len() as u16).to_le_bytes());
        wire.extend_from_slice(&pkt);

        let mut old = OldFrameRx {
            r: TrickleReader {
                chunks: std::collections::VecDeque::new(),
                eof: false,
            },
        };
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut got: Vec<Vec<u8>> = Vec::new();
        for &b in &wire {
            old.r.chunks.push_back(vec![b]);
            loop {
                match old.poll_next_unpin(&mut cx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(p))) => got.push(p),
                    Poll::Ready(Some(Err(e))) => panic!("red-shape control should not error: {e}"),
                    Poll::Ready(None) => panic!("EOF before all data arrived"),
                }
            }
        }
        // Desynchronization confirmed: under the same input, the old shape
        // cannot produce the packet sequence matching the wire (a half-way
        // header is dropped ⇒ subsequent bytes get reassembled into
        // wrong-length frames).
        assert_ne!(
            got,
            vec![pkt.clone()],
            "if the old shape framed correctly, the defect would not exist — this assertion failing means the input does not cover the trickle path"
        );
    }

    /// Regression (observed live during A9 troubleshooting): after the
    /// write pump is gone (session teardown ⇒ data_rx dropped), send
    /// errors immediately; yamux retries poll_write after a write error —
    /// the completed future must already be cleared out of `send_fut`,
    /// otherwise re-polling panics with "async fn resumed after
    /// completion" (killing the mux driver task and delaying dead-link
    /// teardown).
    #[test]
    fn muxio_write_err_then_repoll_returns_err_without_panic() {
        use futures::task::noop_waker;
        use std::task::Context;

        let (data_tx, data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let (_plain_hold, plain_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        drop(data_rx); // write pump gone (no receiver on the channel ⇒ send errors immediately)

        let mut io = MuxIo::new(plain_rx, data_tx);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let first = std::pin::Pin::new(&mut io).poll_write(&mut cx, b"payload");
        match first {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            other => panic!("expected Ready(Err(BrokenPipe)), got {other:?}"),
        }
        // Re-poll (the yamux write-retry shape): must not panic and must
        // yield BrokenPipe again.
        let second = std::pin::Pin::new(&mut io).poll_write(&mut cx, b"payload");
        match second {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            other => panic!("re-poll expected Ready(Err(BrokenPipe)), got {other:?}"),
        }
    }
}
