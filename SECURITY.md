# Whisper security status

## Audit status

Whisper 0.9 is **not formally audited**. It uses the standardized MLS protocol from RFC 9420 through `ts-mls` 1.6.2 and Web Crypto AES-GCM for media, but neither this integration nor the upstream TypeScript implementation should be represented as independently audited. Do not use this release for high-risk or life-safety communications.

The repository now contains a maintainer-reviewed threat model, cryptographic review dossier, authorization-gated passive probe, scheduled dependency/CodeQL review workflow, and incident-response plan. They make an independent assessment reproducible; they do not make the maintainer independent from the implementation. See `docs/THREAT_MODEL.md`, `docs/CRYPTOGRAPHY_REVIEW.md`, `docs/PENETRATION_TEST_PLAN.md`, and `docs/INCIDENT_RESPONSE.md`.

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
- Every uploaded media object receives a fresh random 256-bit AES-GCM key and 96-bit IV. Thumbnails use the same per-object key with a separately generated IV. Keys, IVs, filenames, and MIME types are carried inside encrypted message bodies rather than attachment metadata.
- The R2 boundary accepts only `application/octet-stream` ciphertext with a size fixed at reservation time. D1 stores the conversation, owner, broad media kind, ciphertext sizes, state, and expiry required for authorization and retention.
- Downloads require current conversation membership and use `no-store`; decryption, MIME restoration, playback, and file naming happen only in the browser.
- Persistent rate-limit buckets constrain message, attachment bandwidth, contact, report, device, backup, MLS, profile, and external-provider abuse across worker instances.
- Scoped, expiring abuse restrictions are enforced before high-risk writes. Security events and operations metrics contain bounded metadata and never message content or media keys.
- The public health response contains only component readiness and timing. Detailed metrics and restriction actions require an explicit authenticated operator allowlist.

The service still observes account identifiers, conversation membership, device identifiers, message and attachment timing and sizes, broad attachment kind, retention choice, and report metadata. End-to-end encryption does not hide this metadata.

## Known limitations

- The web application and `ts-mls` dependency need independent cryptographic and application-security audits.
- Browser compromise or successful script injection can read plaintext while the user is using the app.
- Link and recovery workflows currently use copyable codes rather than QR scanning.
- Enabling link/recovery material on a legacy 0.5 device performs an account-authorized identity rotation; contacts will observe a changed safety number.
- Recovery restores account identity and cached history but deliberately does not clone live MLS session state. A surviving member/device must provision the replacement into each chat.
- Backup freshness is user-triggered; background backup scheduling and rollback-resistant backup version transparency are not implemented.
- General group membership UI and call encryption are not implemented.
- Expired and abandoned media is removed opportunistically during attachment API activity. A scheduled production sweep or bucket lifecycle policy is still required to guarantee prompt deletion during periods with no traffic.
- Web clients cannot reliably scan arbitrary encrypted uploads for malware. Type/signature validation is a safety boundary, not antivirus; downloaded files remain untrusted content.
- Online Tenor results are provider-hosted URLs and are not covered by the encrypted upload pipeline. Users must attach a local GIF to receive encrypted R2 storage.
- Critical webhook alerts are inactive until an operator configures and tests `ALERT_WEBHOOK_URL`; stored security events are not a substitute for a staffed incident-response process.
- Infrastructure snapshot, point-in-time recovery, object replication/versioning, external uptime monitoring, alert routing, and recovery drills require operator configuration in the hosting and monitoring platforms. The repository provides a runbook but cannot guarantee those external controls are enabled.
- Automated scanning finds known and modeled classes of weakness but is not a substitute for manual protocol review, adversarial penetration testing, browser/runtime review, or deployment/IAM inspection.
- Safety-number verification is local to a browser and is not automatically synchronized.
- Server-side epoch ordering is intentionally not trusted; clients validate commits through MLS. Operational rate limits and abuse monitoring still need deployment-level configuration.

## Review checklist before production

1. Commission an independent review of the identity binding, key-package lifecycle, Welcome transport, epoch synchronization, and local state persistence.
2. Review every automated dependency and CodeQL finding, verify build provenance, and establish signed/reproducible release artifacts.
3. Audit multi-device linking/removal and recovery ceremonies, including relay compromise, stale backups, concurrent commits, and recovery rollback.
4. Add protocol interoperability, replay, concurrency, corrupted-state, and larger multi-device test-vector suites.
5. Complete CSP/XSS review, rate limiting, telemetry minimization, retention rules, moderation operations, and incident response.
6. Publish the audit report and remediate findings before making an “audited” claim.
