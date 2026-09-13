# Whisper threat model

**Model version:** 1.1 (Whisper 0.10)
**Review date:** August 26, 2026  
**Status:** Maintainer-reviewed; independent review pending

This model describes the deployed web client, Vercel Functions, Turso database, private Vercel Blob ciphertext store, app-owned email/session boundary, optional Google OpenID Connect and Tenor search, and operator integrations. It is a living engineering artifact, not a third-party security certification.

## Security objectives

1. Message and uploaded-media plaintext is available only to authorized conversation devices.
2. A service, database, object-store, network, or backup compromise does not reveal message or media plaintext.
3. Account, device, key-package, group-membership, and epoch changes are authenticated and cannot silently roll back.
4. Lost or removed devices lose future access after the corresponding MLS removal commit is processed.
5. Abuse controls operate without collecting message content, media keys, filenames, or recovery secrets.
6. Security failures are detectable, containable, recoverable, and communicated accurately.

## Assets and sensitivity

| Asset | Sensitivity | Expected location |
| --- | --- | --- |
| Message and control-event plaintext | Critical | Browser memory and encrypted local cache |
| Account/device signing private keys | Critical | Browser IndexedDB; encrypted recovery/link payloads |
| MLS epoch and secret-tree state | Critical | Browser IndexedDB only |
| Media keys, IVs, names, and MIME types | Critical | Inside MLS-encrypted message bodies |
| Recovery key and device-link capability | Critical | User-controlled channel/device only |
| Message/media ciphertext | Confidential | Turso/Blob, browser, backups |
| Identity keys, device bundles, membership | Sensitive metadata | Turso and authorized clients |
| Timing, sizes, broad media kind, reports | Sensitive metadata | Turso and operations boundary |
| Deployment, operator, webhook credentials | Critical | Hosting secret/configuration systems |

## Trust boundaries and data flow

1. **Browser boundary.** Plaintext, private keys, MLS state, attachment keys, and recovery material exist here. A malicious extension, compromised device, or injected same-origin script can cross this boundary.
2. **Identity boundary.** Sites supplies authenticated identity headers. Every protected API must obtain identity only from the trusted hosting dispatcher, never from an application-defined client header.
3. **Function/API boundary.** Vercel Functions authenticate, authorize membership, bound input, apply rate limits/restrictions, and persist only ciphertext plus required metadata.
4. **Turso/Blob boundary.** Turso contains routing/security metadata and ciphertext; private Vercel Blob contains opaque attachment bytes. Neither is trusted with decryption keys.
5. **Peer-device boundary.** Remote participants are authenticated cryptographic members but may be malicious. E2EE protects transport and storage, not the receiver's behavior after decryption.
6. **Operator boundary.** Allowlisted operators can see bounded service/abuse metadata and apply restrictions. They cannot decrypt messages through the application.
7. **Third-party boundary.** Tenor receives online GIF queries and hosts selected remote media. Webhook and monitoring providers receive only deliberately bounded operational events.

## Adversaries and assumptions

- Passive or active network attackers, including replay and traffic analysis.
- Attackers with read/write access to Turso, Vercel Blob, infrastructure backups, or logs.
- Malicious authenticated users, conversation members, linked devices, and blocked users.
- Attackers controlling an expired/stolen device-link code or stale recovery backup.
- Supply-chain attackers affecting JavaScript dependencies, build actions, or deployment credentials.
- Operators or insiders abusing legitimate metadata access.
- Browser compromise, cross-site scripting, malicious extensions, and physical device compromise.

The model assumes standards-compliant Web Crypto, secure randomness, correct TLS termination, a trustworthy current browser/OS, and protected hosting identity headers. Those dependencies remain review targets rather than mathematical guarantees.

## Threat register

| ID | Threat | Primary controls | Residual risk / required verification |
| --- | --- | --- | --- |
| ID-01 | Forged application identity headers | App-owned signed sessions; APIs ignore app-defined device identity headers | Verify production functions cannot bypass the session boundary; test header spoofing |
| ID-02 | Account/device impersonation | Account-signed device keys; device-signed MLS packages; Ed25519 verification | Audit canonical encodings, key substitution, rotation, and race behavior |
| ID-03 | Safety-number substitution | Stable account-key digest and out-of-band comparison | Verification is device-local; users can skip comparison; no key-transparency log |
| MLS-01 | Welcome replay or key-package reuse | Versioned signed packages; unique consumed Welcome record; package rotation | Fuzz concurrency and rollback across multiple browser tabs/devices |
| MLS-02 | Epoch rollback, replay, or message forgery | RFC 9420 private messages and authenticated commits | Add upstream interoperability and corrupted-state vectors; inspect `ts-mls` implementation |
| MLS-03 | Removed device reads future traffic | Account-signed revocation followed by MLS Remove/epoch rotation | Server revocation alone cannot erase already delivered secrets; concurrent offline commits need audit |
| LINK-01 | Device-link interception or relay compromise | 192-bit capability, X25519, HKDF-SHA-256, AES-GCM AAD, compared authentication code, ten-minute expiry | Copyable codes remain phishable; independently test code entropy, lifecycle, and transcript binding |
| REC-01 | Recovery-key theft or weak custody | Random 256-bit offline key; HKDF-SHA-256; AES-GCM; key never uploaded | User screenshots/cloud clipboards can leak keys; no hardware-backed escrow |
| REC-02 | Stale-backup rollback | Backup version and authenticated account binding | No rollback-resistant transparency; restored device must be re-added to live MLS groups |
| MED-01 | Media plaintext/key disclosure in storage | Client AES-256-GCM; independent IVs; opaque private Blob; descriptor inside MLS message | Browser compromise exposes active plaintext; verify nonce uniqueness and deletion lifecycle |
| MED-02 | Malformed or harmful decrypted file | Client allowlists, signatures, size caps, inert ciphertext storage | Validation is not antivirus; recipient must treat downloads as untrusted |
| AUTHZ-01 | IDOR across conversations, attachments, backups, or links | Authenticated account and membership/ownership checks on every API | Penetration test each verb, object state, removed member, and guessed identifier |
| WEB-01 | XSS reads keys/plaintext | React escaping, no raw message HTML, safe URL handling, MIME restoration after download | No strict CSP yet; review every URL/object-URL sink and third-party script path |
| WEB-02 | CSRF or cross-origin state change | Explicit Origin/Sec-Fetch checks on auth writes, SameSite cookies, same-origin JSON fetches | Extend explicit Origin enforcement to every mutating endpoint during independent review |
| AUTH-01 | Password database theft or offline cracking | Unique 128-bit salts and PBKDF2-HMAC-SHA-256 with 600,000 iterations; plaintext passwords are never stored | Password strength still depends on the user; add breached-password screening after privacy review |
| AUTH-02 | Session theft, fixation, or database disclosure | 256-bit opaque tokens, only token hashes in Turso, Secure HttpOnly SameSite=Lax cookies, rotation at every login, logout revocation, 30-day expiry | Add a user-visible session list and global revocation control |
| AUTH-03 | Verification-code guessing or replay | Eight-digit codes, secret-keyed HMAC storage, five attempts, short expiry, one-time consumption, persistent rate limits | Email account compromise remains an account takeover path |
| AUTH-04 | OAuth login CSRF, code interception, or forged Google identity | One-time state tied to an HttpOnly cookie, PKCE S256, nonce, exact redirect URI, RS256 JWKS verification, issuer/audience/expiry/email verification checks | Google availability and account security remain external dependencies |
| META-01 | Traffic analysis or metadata exposure | Minimized schema, bounded ops output, no content in events/webhooks | Service necessarily observes membership, time, size, IP-derived buckets, broad media kind |
| ABUSE-01 | Spam, brute force, or storage exhaustion | Persistent request/bandwidth buckets, restrictions, quotas, retention | Distributed low-rate abuse and new network identities remain possible; tune using production metrics |
| OPS-01 | Operator credential abuse | Explicit allowlist, bounded API, security-event log | External IAM, two-person change control, audit retention, and access reviews require operator setup |
| SUP-01 | Malicious/vulnerable dependency or CI action | Exact direct versions, lockfile, automated audit/baseline, scheduled CI | Transitive packages and registries remain trusted; require lockfile review and rapid patching |
| AVAIL-01 | Vercel, Turso, Blob, identity, or provider outage | Health checks, monitoring runbook, encrypted recovery, infrastructure backups | RPO/RTO, replication, alert routing, and exercises are deployment responsibilities |
| IR-01 | Incident response leaks encrypted content or destroys evidence | Metadata-only events, incident plan, evidence and notification procedures | Needs named responders, external counsel/contact routes, and recurring exercises |

## Abuse cases that E2EE does not solve

- A recipient can copy, screenshot, export, or redistribute decrypted content.
- A compromised endpoint can capture plaintext before encryption or after decryption.
- A malicious participant can send harmful content or abuse invitations, reports, and storage.
- E2EE does not hide account relationships, access timing, ciphertext size, or service availability.
- Blocking prevents future application interactions; it cannot retract content already received.

## Required verification

- Run `npm run security:review` on every release and the passive authorized probe against staging.
- Penetration-test every object reference and state transition listed in `docs/PENETRATION_TEST_PLAN.md`.
- Independently review the inventory and questions in `docs/CRYPTOGRAPHY_REVIEW.md`.
- Exercise `docs/INCIDENT_RESPONSE.md` and the recovery drill in `docs/OPERATIONS.md` at least annually and quarterly, respectively.
- Re-review this model after a cryptographic, authentication, storage, third-party, or trust-boundary change.

Risk acceptance must name an owner, expiry date, affected threat IDs, rationale, and compensating controls. An unresolved Critical or High finding blocks an audited/production-ready claim.
