# Whisper incident-response plan

**Plan version:** 1.0  
**Review date:** August 26, 2026  
**Exercise status:** Tabletop pending

This plan covers confidentiality, integrity, availability, abuse, supply-chain, and cryptographic incidents affecting Whisper. It complements `docs/OPERATIONS.md`; it does not replace the operator's legal, regulatory, insurance, hosting, or employment procedures.

## Preparation and authority

Before production use, assign named primary and backup owners for incident command, security/engineering, operations, privacy/legal, communications, and user support. Maintain out-of-band contacts, hosting/source emergency access, a private evidence repository, an approved status channel, and current service/data-flow inventories.

The incident commander may pause deployments, disable optional providers, restrict risky writes, revoke operator/deployment credentials, and isolate an affected version. Only authorized hosting staff may restore data or change routing. Only the privacy/legal owner approves breach/regulatory statements. No responder may request message plaintext or weaken E2EE merely to simplify investigation.

## Severity and response targets

| Severity | Examples | Acknowledge / command | Update cadence |
| --- | --- | --- | --- |
| SEV-1 Critical | Active key/plaintext compromise, signing-key or deployment takeover, broad cross-account access, destructive compromise | 15 minutes / 30 minutes | At least hourly |
| SEV-2 High | Exploitable stored XSS, constrained authorization bypass, major outage/data integrity issue, malicious production dependency | 30 minutes / 60 minutes | At least every 2 hours |
| SEV-3 Medium | Limited metadata exposure, degraded redundancy, recurring targeted abuse, important control failure without active exploitation | 4 hours / business day | Daily |
| SEV-4 Low | Hardening gap, unsuccessful attempt, minor isolated degradation | 2 business days | At milestones |

These are operational goals, not guarantees. When uncertain, start one level higher and de-escalate with evidence.

## Response lifecycle

### 1. Detect and declare

- Record reporter/source, UTC time, observed behavior, affected version/region/accounts, and the least-sensitive supporting evidence.
- Create an incident ID, severity, commander, private timeline, and next-update time.
- Preserve the relevant deployed commit, lockfile, build/deployment records, bounded security events, provider audit logs, D1/R2 metadata, and access logs according to policy.
- Treat unverified claims as hypotheses. Do not state that encrypted content was exposed merely because ciphertext or metadata was accessed.

### 2. Contain

- Prefer reversible, narrowly scoped containment: disable an optional integration, block a compromised credential, restrict an abusive account/scope, stop a deployment, or make a risky path unavailable.
- If application integrity is uncertain, freeze releases and risky writes while keeping read/recovery paths available when safe.
- Rotate deployment, source, operator, webhook, and provider credentials that may be exposed. Do not rotate user identity keys on a user's behalf or claim that credential rotation fixes stolen plaintext/MLS state.
- For a malicious client release, remove it from service, preserve its artifacts, and publish a safe warning. Assume it could read plaintext available to that origin.

### 3. Eradicate and remediate

- Identify root cause and every trust boundary crossed; search for variants and persistence.
- Fix on a protected branch, add a regression test, review the patch with two people, run `npm run security:review`, and retest the exploit in isolation.
- Rebuild from a known-good dependency lockfile and controlled environment. Review lifecycle scripts and provenance after supply-chain incidents.
- Do not delete evidence or attacker-created records until the evidence owner approves preservation.

### 4. Recover

- Restore D1/R2 from a verified recovery point only when integrity requires it; first validate in isolation using `docs/OPERATIONS.md`.
- Deploy the exact reviewed commit, validate `/api/health`, run the authorized passive probe, and monitor authentication, message/media success, errors, security events, storage, and reports.
- Re-enable paused functions in stages. Record actual recovery point, data loss, downtime, and any user action needed (safety-number re-verification, device removal, or re-provisioning).

### 5. Notify and learn

- Privacy/legal determines notification duties, deadlines, recipients, and law-enforcement/regulator coordination for the actual jurisdictions and data affected.
- Communications distinguish plaintext, keys, ciphertext, identity/membership metadata, timing/size metadata, and service availability. State facts, uncertainty, user actions, and the next update; never overclaim encryption protection.
- Within five business days of containment, produce a blameless review with timeline, root cause, impact, detection/response gaps, what went well, corrective owners/deadlines, risk acceptances, and a public-safe summary.

## Playbooks

### Suspected web-client/XSS or deployment compromise

1. Treat plaintext visible during the affected session and browser-held key material as potentially exposed.
2. Remove the affected release and third-party script, revoke deployment/source credentials, preserve artifacts and CSP/browser reports.
3. Determine first/last malicious execution and affected sessions; advise affected users to remove suspect devices and verify safety numbers after a clean release.
4. Audit every same-origin script, HTML/URL sink, build input, and service-worker/cache path before recovery.

### Database, R2, log, or backup access

1. Identify exact tables/objects/fields and access window. Ciphertext access is still a confidentiality incident even when decryption keys were absent.
2. Verify whether any attachment keys, MLS state, recovery/link material, identity private keys, or plaintext entered storage/logging contrary to design.
3. Revoke infrastructure credentials, close the access path, validate object/database integrity, and assess metadata exposure and legal duties.
4. Do not force cryptographic identity rotation unless evidence shows private identity material was exposed.

### Account, device, link, or recovery compromise

1. Help the user remove the affected device, finish MLS Remove commits, compare safety numbers, and preserve only necessary security metadata.
2. Expire active link sessions and restrict suspicious writes when authorized; examine code reuse, device registrations, backup changes, and membership events.
3. Explain that revocation protects future epochs but cannot retract plaintext or secrets already obtained by the compromised device.

### Cryptographic vulnerability

1. Convene an independent cryptographer; freeze claims and affected protocol changes.
2. Determine primitive, implementation, composition, state, and interoperability impact, plus which keys/epochs/devices are exposed.
3. Design a versioned migration with downgrade protection, peer compatibility, key/session rotation, user verification guidance, and rollback plan.
4. Avoid silently inventing a replacement protocol during the incident. Publish reviewed migration details and residual risk.

### Malicious or vulnerable dependency/CI action

1. Stop deployments; preserve registry metadata, package tarballs, lockfile, CI logs/artifacts, runner provenance, and tokens.
2. Revoke tokens accessible to builds and inspect publish/lifecycle scripts and generated output.
3. Pin/remove the component, rebuild from trusted sources, compare artifacts, run CodeQL/baseline/tests, and review whether browser-delivered code accessed plaintext.

### Abuse campaign or denial of service

1. Apply the narrowest expiring restriction/rate adjustment that contains harm without reading messages.
2. Protect reporting, account recovery, health, and operator access; coordinate with hosting protections for network-scale attacks.
3. Record privacy-preserving indicators and tune persistent buckets. Do not use message decryption as an abuse-control shortcut.

## Evidence handling

- Use UTC, preserve originals read-only, hash exported artifacts, record collector/tool/source/time, and maintain a chain-of-custody log.
- Minimize exports; redact tokens, recovery/link codes, email addresses, and unrelated user metadata from tickets and chat.
- Never copy user ciphertext or metadata into public issues. Store access is role-limited, logged, time-bound, and retained according to the approved incident/legal-hold schedule.

## Communication templates

**Internal declaration:** `INC-[id] [severity] declared at [UTC]. Observed: [facts]. Potential scope: [systems/data]. Commander: [name]. Containment: [action]. Next update: [UTC].`

**User update:** `We identified [accurate event] between [times]. The affected data is [specific categories]; we have [no evidence/evidence] that message plaintext or keys were involved. We [containment]. You should [concrete action]. We will update by [time/link].`

## Exercises and maintenance

- Conduct a SEV-1 tabletop at least annually and after major authentication/cryptographic architecture changes.
- Exercise restore/recovery quarterly under `docs/OPERATIONS.md`.
- Test incident contacts, operator access, webhook delivery, evidence storage, and user/status communications at least quarterly.
- Update this plan after each exercise/incident and whenever ownership, providers, data flows, or legal obligations change.
