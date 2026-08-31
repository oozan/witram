# Whisper production operations

This runbook is part of the production boundary. Review it before each release and after every material incident.

## Service objectives and ownership

Assign a named service owner, privacy contact, security contact, and backup operator before inviting users. Record an approved recovery-point objective (RPO) and recovery-time objective (RTO); the application cannot choose acceptable data-loss or downtime thresholds for the operator.

## Monitoring and alerting

- Probe `GET /api/health` from an external monitor at least every five minutes. Alert after two consecutive non-200 responses and resolve only after two healthy responses.
- Set `OPS_ADMIN_USER_IDS` to the comma-separated authenticated account IDs of the minimum necessary operators. `GET /api/operations` returns bounded 24-hour security, report, restriction, and attachment counts without message content.
- Set `ALERT_WEBHOOK_URL` to an HTTPS endpoint owned by the operator. Critical application events are persisted first and then sent to this endpoint. Test delivery after configuration and quarterly thereafter.
- Alert on health failures, sustained rate-limit increases, report backlog growth, unexpected restriction changes, failed deployments, and storage/database capacity thresholds.
- Never send message ciphertext, keys, filenames, email addresses, report details, or recovery material to alerting systems.
- The Worker runs scheduled maintenance at minute 17 of every hour. It deletes expired or abandoned R2 ciphertext, expires authentication and device-link artifacts, prunes limiter buckets, and applies the documented metadata-retention windows. Monitor `scheduled_maintenance` events and Worker cron failures.

## Abuse response

1. Triage reports using metadata only. Do not request plaintext unless a reporter voluntarily chooses to provide it through an approved channel.
2. Encourage immediate blocking when there is ongoing contact abuse.
3. An authorized operator may apply an expiring `all`, `messages`, `media`, or `contacts` restriction through `POST /api/operations`. Record a concise reason without sensitive narrative.
4. Preserve relevant security-event and report records under the legal hold policy when required. Never weaken or bypass encryption to investigate.
5. Revoke a restriction after review or let its explicit expiry end it. Document decisions outside the application in the operator’s controlled case-management system.
6. Escalate credible threats, child safety issues, account compromise, or legal requests through the operator’s established emergency and legal procedures.

## Backup policy

Application-level encrypted account recovery backups protect user identity material and cached history, but they are not a substitute for infrastructure backups.

The operator must configure and verify provider-managed protection for both logical bindings:

- `DB`: scheduled snapshots or point-in-time recovery that cover schema and data.
- `MEDIA`: object versioning, replication, or backup consistent with selected user retention. Backup expiry must not extend a user-selected deletion period.

Keep backup access separate from routine deployment access, require strong authentication, encrypt exports, log restores, and document retention. Do not export media decryption keys because the service does not possess them.

## Quarterly recovery drill

1. Create an isolated recovery environment with no production outbound messaging or alert side effects.
2. Restore the latest database recovery point and verify the expected migration set, including `rate_limit_buckets`, `security_events`, `abuse_restrictions`, and `attachments`.
3. Restore or attach the encrypted-media backup and verify ciphertext object counts and a sample of object hashes without decrypting content.
4. Run the build and automated boundary tests against the restored environment.
5. With designated test accounts, verify sign-in, contacts, an MLS message, an encrypted attachment, device recovery, blocking/reporting, rate limiting, and retention deletion.
6. Measure achieved RPO and RTO, record gaps, destroy the isolated restore, and confirm all temporary credentials and copies were removed.

Verify the isolated SQLite/D1 restore without changing it. If media was restored, generate a manifest containing each ciphertext object key, byte size, and SHA-256 digest using the documented example schema, then include it in the check:

```sh
npm run recovery:verify -- --database=/absolute/path/to/restored.sqlite --media-manifest=/absolute/path/to/media-manifest.json
```

The verifier opens the database read-only, runs SQLite integrity and foreign-key checks, verifies every required production table, reports bounded record counts, and confirms every active attachment and encrypted thumbnail exists in the hashed media manifest. It never prints object keys, account data, ciphertext, or message content.

## Disaster recovery

1. Declare the incident, stop risky writes if data consistency is uncertain, and preserve operational logs.
2. Identify the last known-good application version, database recovery point, and encrypted object-storage state.
3. Restore into isolation first. Validate referential integrity, migrations, active restrictions, attachment metadata/object presence, and health checks.
4. Rotate deployment, operations, webhook, and source credentials when compromise is possible. Do not rotate end-user cryptographic identities on their behalf.
5. Promote the restored environment only after two-person review. Monitor errors, reports, rate limits, and message/attachment success closely.
6. Notify affected users and regulators when required by the incident plan and applicable law. Be precise about metadata versus encrypted content exposure.
7. Complete a blameless post-incident review with corrective owners and deadlines.

## Release checklist

Run the passive production gate after deployment:

```sh
WHISPER_BASE_URL=https://your-host.example SMOKE_TEST_AUTHORIZATION=I_HAVE_AUTHORIZATION npm run smoke:production
```

Run the bounded health-only load smoke only against a target for which you have explicit authorization. It is hard-capped at 1,000 requests and 25 concurrent requests:

```sh
WHISPER_BASE_URL=https://staging.example LOAD_ALLOW_REMOTE=true LOAD_TEST_AUTHORIZATION=I_HAVE_AUTHORIZATION npm run smoke:load
```

- Automated lint, build, boundary tests, dependency audit, and migration inspection pass.
- The exact tested commit is pushed and packaged.
- Database migrations are present and forward-compatible; a recovery point exists before applying them.
- Health monitoring, alert delivery, operations access, retention cleanup, and backup freshness are verified.
- The hourly Cron Trigger is enabled in the deployed Worker and a recent `scheduled_maintenance` event is visible.
- Privacy Policy, Terms, security limitations, subprocessors, operator identity, governing terms, and contact routes are reviewed for the actual deployment and jurisdiction.
