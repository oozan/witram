# Whisper cryptography review dossier

**Review target:** Whisper 0.9  
**Status:** Internal implementation inventory; independent cryptography audit pending

This document gives an external cryptographer a precise starting point. It does not certify the integration, the browser runtime, or `ts-mls`.

## Protocol and primitive inventory

| Purpose | Construction | Key/nonce source | Binding and storage |
| --- | --- | --- | --- |
| Direct-chat group protocol | RFC 9420 MLS via `ts-mls` 1.6.2, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | MLS implementation and Web Crypto RNG | Group state remains in IndexedDB; Worker transports opaque private messages, commits, and Welcomes |
| Account identity | Ed25519 | Web Crypto generated; imported non-exportable after wrapping | Stable public key anchors safety number and signs device identities |
| Device identity | Ed25519 | Fresh per device | Account signature binds user ID, device ID, name, and public key; device signs MLS key packages |
| Saved Messages | AES-256-GCM | Non-exportable Web Crypto key; fresh 96-bit IV per encryption | IndexedDB key, D1 ciphertext/IV |
| Device linking | X25519 + HKDF-SHA-256 + AES-256-GCM | Fresh ephemeral key pairs, 192-bit capability, fresh 96-bit IV | HKDF info `whisper-device-link-v1`; link ID is AES-GCM AAD; user compares derived authentication code |
| Recovery backup | HKDF-SHA-256 + AES-256-GCM | Random 256-bit recovery secret, random 256-bit salt, fresh 96-bit IV | HKDF info `whisper-encrypted-backup-v1`; user ID is AAD; secret never uploaded |
| Media and thumbnail encryption | AES-256-GCM | Fresh 256-bit key per upload; separate random 96-bit IV for original and thumbnail | R2 receives ciphertext only; key/IV/name/MIME live inside an MLS-encrypted descriptor |
| Safety number | SHA-256 over sorted stable account public keys | Public identities | Domain prefix `whisper-safety-v1`; compared outside Whisper |
| Device revocation | Ed25519 signature | Account identity key | Domain prefix `whisper-device-revoke-v1`, user, target device, timestamp |

All randomness is requested through `crypto.getRandomValues` or Web Crypto key generation. Direct dependency versions are exact and the complete npm graph is locked by `package-lock.json`.

The scheduled workflow runs CodeQL analysis without uploading SARIF because repository-level GitHub Code Scanning is not assumed to be enabled. The repository owner should enable that feature and remove `upload: false` when plan and policy permit centralized alert ingestion.

## Key lifecycle

1. The first device creates a stable account signing key and a distinct device signing key.
2. The account key signs the device binding. The device key signs each versioned, one-time MLS key package.
3. The server checks bindings and monotonic package versions but is not trusted to create or decrypt MLS state.
4. A Welcome consumes one published package. The joining device rotates its package after consumption.
5. MLS commits advance epochs. User-triggered rotation and member/device changes create authenticated commits.
6. Linking transfers the stable account private key only inside a link-session AEAD channel; the new device creates its own device key and MLS packages.
7. Removal is account-authorized and must be followed by MLS Remove commits. Already received plaintext and old epoch material cannot be clawed back.
8. Recovery restores the account identity and cached encrypted history, not live MLS session secrets. A surviving member must provision the replacement into each active conversation.

## Review invariants

An independent reviewer should prove or falsify each invariant against code and adversarial tests:

- Account, device, and key-package identifiers have one canonical signed encoding with unambiguous domain separation.
- A server cannot replace a device key, decrease a key-package version, reuse a Welcome, or add a device without a valid account/device signature chain.
- MLS messages reject replays, wrong epochs, corrupted transcripts, forged commits, and credentials not bound to the expected account/device.
- Concurrent commits and browser tabs converge or fail closed without reusing consumed state.
- Every AES-GCM encryption uses a nonce unique under its key. Media original and thumbnail IVs are independently generated.
- Link keys bind both ephemeral public keys, the capability, link identifier, role, and protocol version strongly enough to prevent unknown-key-share, reflection, and transcript substitution.
- Authentication-code comparison covers the same transcript used by the transfer key and cannot be bypassed by UI or API state races.
- Recovery decrypts only backups bound to the expected user/version and rejects truncation, rollback, malformed lengths, and key confusion.
- Private byte buffers are erased when possible and no secret is serialized into logs, D1 metadata, R2 metadata, URLs, analytics, or webhook events.
- Device removal ordering cannot present “removed” before the MLS epoch that excludes the device is durably synchronized.

## Code review map

- `app/mls-crypto.ts`: identity creation/wrapping, signed bindings, MLS lifecycle, safety numbers, linking, recovery, revocation.
- `app/client-crypto.ts`: Saved Messages AES-GCM vault.
- `app/media-crypto.ts`: media validation, key/IV generation, encryption, thumbnail handling, decryption.
- `app/api/keys/route.ts`: public bundle validation, monotonic versions, identity rotation and revocation.
- `app/api/mls/welcomes/route.ts`: one-time package consumption and Welcome delivery.
- `app/api/mls/events/route.ts`: public commit transport and membership authorization.
- `app/api/messages/route.ts`: MLS-only enforcement for multi-account conversations.
- `app/api/devices/links/route.ts`: capability rendezvous lifecycle and bounded encrypted relay.
- `app/api/backups/route.ts`: ciphertext-only backup storage.
- `app/api/attachments/`: ciphertext size/state/retention and membership authorization.

## Known concerns and open questions

1. `ts-mls` and this integration have no published independent audit known to this project. Review the exact locked source and its transitive dependencies.
2. Browser IndexedDB protects keys from server compromise, not same-origin script injection, malicious extensions, device malware, or an unlocked local profile.
3. There is no key-transparency service. Out-of-band safety-number comparison is the defense against a compromised identity directory.
4. Device-link codes are copyable and phishable; there is no QR transcript scanner or proximity proof.
5. Recovery has no transparency-backed anti-rollback counter and relies on user custody of a high-entropy key.
6. Safety verification state is local and does not synchronize across verified devices.
7. Metadata and traffic-analysis protections are intentionally out of scope for the cryptographic payload protocol.
8. Content Security Policy is not yet strict enough to be considered a hardened key-bearing web-client boundary.

## Independent audit acceptance criteria

The reviewer must be organizationally separate from implementation, disclose scope and methodology, identify the exact commit and dependency lockfile, include exploit/reproduction evidence, assign severity, and retest fixes. The report must cover protocol composition—not merely the primitive names—and explicitly state exclusions.

Whisper may claim “independently reviewed” only after publishing the review scope, reviewed commit, reviewer identity, report or substantive summary, remediation status, and residual accepted risks. Until then, product and repository copy must say **independent review pending**.
