# Whisper security status

## Audit status

Whisper 0.5 is **not formally audited**. It uses the standardized MLS protocol from RFC 9420 through `ts-mls` 1.6.2, but neither this integration nor the upstream TypeScript implementation should be represented as independently audited. Do not use this release for high-risk or life-safety communications.

## Implemented protocol boundary

- Each account creates an Ed25519 identity key. Its non-exportable private key stays in IndexedDB.
- Each browser device creates a distinct Ed25519 identity key signed by the account key.
- Each device publishes a versioned MLS key package signed by its device key.
- The client verifies the account-to-device signature, device-to-key-package signature, MLS credential binding, and the MLS key-package signature before adding a member.
- A key-package version can produce only one server-side Welcome record. The recipient rotates its published package after joining.
- Direct messages and control events are MLS private messages. Public MLS commits rotate the epoch and are authenticated by MLS.
- The safety number is derived from both stable account public keys and must be compared over an independent channel.
- Private key material and consumed MLS secrets are kept client-side; temporary secret buffers exposed by the library are zeroed where its API provides them.

The service still observes account identifiers, conversation membership, device identifiers, message timing and sizes, and report metadata. End-to-end encryption does not hide this metadata.

## Known limitations

- The web application and `ts-mls` dependency need independent cryptographic and application-security audits.
- Browser compromise or successful script injection can read plaintext while the user is using the app.
- Account identity transfer to a second device is not implemented. A second unlinked browser is rejected instead of silently replacing the identity.
- Secure backup, recovery, device-link QR ceremonies, device removal commits, group membership changes, encrypted attachments, and call encryption are not implemented.
- Safety-number verification is local to a browser and is not automatically synchronized.
- Server-side epoch ordering is intentionally not trusted; clients validate commits through MLS. Operational rate limits and abuse monitoring still need deployment-level configuration.

## Review checklist before production

1. Commission an independent review of the identity binding, key-package lifecycle, Welcome transport, epoch synchronization, and local state persistence.
2. Pin and audit the complete dependency tree, add reproducible builds, and establish a vulnerability-response process.
3. Add multi-device linking/removal and recovery ceremonies with explicit user confirmation.
4. Add protocol interoperability, replay, concurrency, corrupted-state, and multi-device test vectors.
5. Complete CSP/XSS review, rate limiting, telemetry minimization, retention rules, moderation operations, and incident response.
6. Publish the audit report and remediate findings before making an “audited” claim.
