# Security Policy

## Reporting a Vulnerability

flock-protocol is a cryptographic protocol library; security reports
take precedence over all ordinary issues.

**Please do not report security vulnerabilities through public issues,
PRs, discussion boards, or any public channel.**

Use GitHub's private vulnerability reporting channel:

1. Open this repository's page and go to the **Security** tab;
2. Choose **Report a vulnerability** (private vulnerability reporting);
3. Describe per the template: affected versions, attack preconditions,
   impact scope, reproduction steps (attach a PoV inside the report if
   you have one; the report itself is non-public).

GitHub private vulnerability reporting docs:
<https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability>

If that channel is unavailable (e.g. the repository has not enabled it),
contact the maintainer email (see the repository About or README), with
the subject prefixed `[security]`.

### Expected response cadence

- **Acknowledgment**: within 3 business days;
- **Initial assessment** (accept/reject, impact rating): within 7
  business days;
- **Fix and advisory**: scheduled by severity; fixes ship with regular
  releases, accompanied by a GitHub Security Advisory (CVE IDs requested
  as needed).

Please give us a reasonable fix window before disclosing details; we
commit to not pursuing action against good-faith reporters (no legal
recourse).

## Scope

- Cryptographic constructions, protocol logic, and implementation flaws
  in this crate (src/, tests/, benches/);
- Parts of known dependency vulnerabilities that affect this crate
  (please report those too; we follow up with upgrades through the
  regular channels).

Out of scope: attack surfaces requiring physical access or an already
compromised OS, theoretical attacks with no realistic preconditions,
DoS-style resource exhaustion (unless triggerable remotely at negligible
cost in a way that affects tunnel availability).

## Advisory channel

Security-fix advisories are published via GitHub **Security Advisories**
(the repository's Security tab), and mirrored into the corresponding
release notes.
