# Whisper security status

## Audit status

Whisper 0.6 is **not formally audited**. It uses the standardized MLS protocol from RFC 9420 through `ts-mls` 1.6.2, but neither this integration nor the upstream TypeScript implementation should be represented as independently audited. Do not use this release for high-risk or life-safety communications.

## Implemented protocol boundary

- Each account creates an Ed25519 identity key. Its non-exportable private key stays in IndexedDB.
- Each browser device creates a distinct Ed25519 identity key signed by the account key.
- Each device publishes a versioned MLS key package signed by its device key.
- The client verifies the account-to-device signature, device-to-key-package signature, MLS credential binding, and the MLS key-package signature before adding a member.
- A key-package version can produce only one server-side Welcome record. The recipient rotates its published package after joining.
- Direct messages and control events are MLS private messages. Public MLS commits rotate the epoch and are authenticated by MLS.
- The safety number is derived from both stable account public keys and must be compared over an independent channel.
- Private key material and consumed MLS secrets are kept client-side; temporary secret buffers exposed by the library are zeroed where its API provides them.
- Device linking uses a 192-bit capability, ephemeral X25519, HKDF-SHA-256, AES-256-GCM, link-specific authenticated data, and a human-compared authentication code. The relay never receives the capability or shared secret.
- A linked device receives the stable account signing identity but creates a distinct device identity and a pool of one-time MLS key packages.
- Existing devices add a linked device to each chat with a separate MLS Add commit and Welcome. Device removal is account-signed and produces MLS Remove commits before server revocation.
- Recovery backups contain the wrapped account signing key and locally cached history, then use HKDF-SHA-256 and AES-256-GCM under a random 256-bit recovery key that is never uploaded.

The service still observes account identifiers, conversation membership, device identifiers, message timing and sizes, and report metadata. End-to-end encryption does not hide this metadata.

## Known limitations

- The web application and `ts-mls` dependency need independent cryptographic and application-security audits.
- Browser compromise or successful script injection can read plaintext while the user is using the app.
- Link and recovery workflows currently use copyable codes rather than QR scanning.
- Enabling link/recovery material on a legacy 0.5 device performs an account-authorized identity rotation; contacts will observe a changed safety number.
- Recovery restores account identity and cached history but deliberately does not clone live MLS session state. A surviving member/device must provision the replacement into each chat.
- Backup freshness is user-triggered; background backup scheduling and rollback-resistant backup version transparency are not implemented.
- General group membership UI, encrypted attachments, and call encryption are not implemented.
- Safety-number verification is local to a browser and is not automatically synchronized.
- Server-side epoch ordering is intentionally not trusted; clients validate commits through MLS. Operational rate limits and abuse monitoring still need deployment-level configuration.

## Review checklist before production

1. Commission an independent review of the identity binding, key-package lifecycle, Welcome transport, epoch synchronization, and local state persistence.
2. Pin and audit the complete dependency tree, add reproducible builds, and establish a vulnerability-response process.
3. Audit multi-device linking/removal and recovery ceremonies, including relay compromise, stale backups, concurrent commits, and recovery rollback.
4. Add protocol interoperability, replay, concurrency, corrupted-state, and larger multi-device test-vector suites.
5. Complete CSP/XSS review, rate limiting, telemetry minimization, retention rules, moderation operations, and incident response.
6. Publish the audit report and remediate findings before making an “audited” claim.
