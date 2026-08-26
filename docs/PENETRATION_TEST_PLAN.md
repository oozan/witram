# Whisper penetration-test plan

**Status:** Repeatable internal probe implemented; independent penetration test pending

## Authorization and rules of engagement

Testing requires written authorization naming the target, dates, source addresses, tester, emergency contact, permitted techniques, and data-handling rules. Prefer an isolated production-equivalent staging environment with synthetic accounts and media.

Never test another user's deployment, attempt persistence, target hosting-provider infrastructure, exfiltrate real user data, weaken encryption, send harmful files to people, or perform denial-of-service/load testing without separate written approval. Stop on unexpected plaintext, keys, personal data, cross-tenant access, material availability impact, or evidence of an unrelated compromise.

The repository probe is passive, rate-bounded, secret-redacting, and fails closed unless the operator explicitly sets `SECURITY_TEST_AUTHORIZATION=I_HAVE_AUTHORIZATION`. Remote targets also require `SECURITY_ALLOW_REMOTE=true`.

```bash
SECURITY_TEST_AUTHORIZATION=I_HAVE_AUTHORIZATION npm run security:probe -- --target=http://localhost:3000
```

For an authorized private Sites staging deployment, supply its bypass token as `OAI_SITES_BYPASS_TOKEN`; the probe never prints it. Do not place tokens in shell history or commit them.

## Test matrix

| Area | Required cases |
| --- | --- |
| Identity | Missing, duplicated, malformed, and spoofed identity headers; dispatcher bypass; disabled/deleted identity; email/display-name confusion |
| Authorization/IDOR | Every method on conversations, messages, attachments, keys, Welcomes, events, links, backups, blocks, reports, and operations using guessed IDs and non-member/removed/blocked accounts |
| Session and cross-origin | Origin/Sec-Fetch handling, CSRF, CORS preflight, redirect/login behavior, cache leakage, logout, multiple tabs |
| Input handling | Oversized/truncated JSON, duplicate keys, Unicode normalization, invalid base64, integer boundaries, content-type confusion, malformed MLS objects |
| Browser/XSS | Message URLs, names, GIF/provider data, filenames after decryption, object URLs, errors, exports, SVG/HTML media, DOM clobbering, dependency scripts |
| MLS | Replayed/private messages, replayed/parallel commits, wrong epoch/group/sender, reused packages/Welcomes, forged bindings, credential substitution, state corruption |
| Linking/recovery | Stolen/expired/replayed codes, role reflection, transcript substitution, auth-code mismatch, concurrent approval, stale backup, wrong account/key/version |
| Media | Reservation/upload mismatch, object-key guessing, pending/finalized/deleted/expired states, range/cache behavior, size/type/signature bypass, thumbnail substitution |
| Abuse/availability | Distributed invitation/message/report/storage pressure, rate-limit key evasion, restriction-scope bypass, bounded responses; destructive load only with separate approval |
| Operations | Allowlist parsing, privilege confusion, webhook SSRF/configuration, sensitive event fields, health/metrics disclosure, audit-log integrity |
| Supply chain | Lockfile integrity, lifecycle scripts, typosquatting, known advisories, action versions, build provenance, secret exposure in artifacts/logs |

## Evidence and finding format

Record the exact commit, lockfile hash, deployment version, browser, tester, timestamp, synthetic account roles, request/response evidence with secrets removed, impact, likelihood, severity, reproduction steps, affected threat IDs, recommended fix, owner, deadline, and retest result.

- **Critical:** practical plaintext/key compromise, cross-tenant takeover, signing-key compromise, or broad unauthenticated destructive access.
- **High:** reliable account/device compromise, authorization bypass, stored XSS in key-bearing origin, or material integrity failure.
- **Medium:** constrained data exposure, security-control bypass needing strong preconditions, or meaningful abuse/availability weakness.
- **Low/Informational:** hardening issue with limited direct impact or defense-in-depth recommendation.

Critical findings trigger the incident plan immediately. Critical/High findings block release and any “audited” claim until independently retested. Medium findings require a documented owner and deadline; accepted risks require owner, rationale, compensating control, and expiry.

## Deliverables

The external tester supplies an executive summary, full technical report, tested endpoint/method matrix, exclusions, raw evidence bundle, findings ledger, and remediation retest letter. The project publishes a safe summary that names the reviewed commit and unresolved material risk without exposing exploit details prematurely.
