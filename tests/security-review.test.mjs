import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("ships a complete review dossier without claiming an independent audit", async () => {
  const [threats, crypto, penetration, incident, security, page] = await Promise.all([
    readFile(new URL("../docs/THREAT_MODEL.md", import.meta.url), "utf8"),
    readFile(new URL("../docs/CRYPTOGRAPHY_REVIEW.md", import.meta.url), "utf8"),
    readFile(new URL("../docs/PENETRATION_TEST_PLAN.md", import.meta.url), "utf8"),
    readFile(new URL("../docs/INCIDENT_RESPONSE.md", import.meta.url), "utf8"),
    readFile(new URL("../SECURITY.md", import.meta.url), "utf8"),
    readFile(new URL("../app/security/page.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(threats, /Threat register/);
  assert.match(threats, /ID-01/);
  assert.match(crypto, /Review invariants/);
  assert.match(crypto, /MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519/);
  assert.match(penetration, /Authorization and rules of engagement/);
  assert.match(incident, /Suspected web-client\/XSS/);
  assert.match(incident, /Cryptographic vulnerability/);
  assert.match(security, /not formally audited/i);
  assert.match(page, /Independent review is pending/i);
  assert.match(page, /have not completed an independent security audit/i);
  assert.doesNotMatch(`${security}\n${page}`, /independent audit (?:is )?complete|independent review (?:is )?complete/i);
});

test("security automation is scheduled, authorization-gated, and fail closed", async () => {
  const [workflow, dependabot, probe, baseline, manifest] = await Promise.all([
    readFile(new URL("../.github/workflows/security-review.yml", import.meta.url), "utf8"),
    readFile(new URL("../.github/dependabot.yml", import.meta.url), "utf8"),
    readFile(new URL("../scripts/security-probe.mjs", import.meta.url), "utf8"),
    readFile(new URL("../scripts/security-baseline.mjs", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);
  assert.match(workflow, /schedule:/);
  assert.match(workflow, /npm audit --omit=dev --audit-level=high/);
  assert.match(workflow, /github\/codeql-action\/analyze@v4/);
  assert.match(workflow, /actions\/dependency-review-action@v5/);
  assert.match(dependabot, /package-ecosystem: npm/);
  assert.match(dependabot, /package-ecosystem: github-actions/);
  assert.match(probe, /I_HAVE_AUTHORIZATION/);
  assert.match(probe, /Refusing a remote target/);
  assert.match(probe, /mode: "passive"/);
  assert.doesNotMatch(probe, /method:\s*["'](?:POST|PUT|PATCH|DELETE)/);
  assert.match(baseline, /process\.exitCode = 1/);
  assert.match(manifest, /"security:review"/);
});

test("browser push is opt-in, encrypted, generic, and constrained to browser push services", async () => {
  const [sender, route, worker, client, privacy] = await Promise.all([
    readFile(new URL("../app/api/_lib/web-push.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/push/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../public/whisper-sw.js", import.meta.url), "utf8"),
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/privacy/page.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(sender, /"content-encoding": "aes128gcm"/);
  assert.match(sender, /authorization: `vapid/);
  assert.match(sender, /New encrypted message/);
  assert.match(sender, /pushServiceHosts/);
  assert.doesNotMatch(sender, /display_name|conversation.*title|plaintext.*payload/i);
  assert.match(route, /requireSameOrigin/);
  assert.match(route, /existing\.user_id !== current\.userId/);
  assert.match(worker, /showNotification/);
  assert.match(worker, /New encrypted message/);
  assert.match(client, /Notification\.requestPermission\(\)/);
  assert.match(client, /setPrivateNotifications/);
  assert.match(privacy, /push provider can observe delivery timing/i);
});

test("production smoke and load probes are bounded and require remote authorization", async () => {
  const [smoke, load, manifest, operations] = await Promise.all([
    readFile(new URL("../scripts/production-smoke.mjs", import.meta.url), "utf8"),
    readFile(new URL("../scripts/load-smoke.mjs", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../docs/OPERATIONS.md", import.meta.url), "utf8"),
  ]);
  assert.match(smoke, /SMOKE_TEST_AUTHORIZATION/);
  assert.match(smoke, /frame-ancestors 'none'/);
  assert.doesNotMatch(smoke, /method:\s*["'](?:POST|PUT|PATCH|DELETE)/);
  assert.match(load, /Math\.min\(1_000/);
  assert.match(load, /Math\.min\(25/);
  assert.match(load, /LOAD_ALLOW_REMOTE/);
  assert.match(load, /\/api\/health/);
  assert.match(manifest, /"smoke:production"/);
  assert.match(manifest, /"smoke:load"/);
  assert.match(operations, /bounded health-only load smoke/i);
});

test("recovery verification is read-only and covers database and encrypted media integrity", async () => {
  const [verifier, manifest, operations, packageManifest] = await Promise.all([
    readFile(new URL("../scripts/verify-recovery.mjs", import.meta.url), "utf8"),
    readFile(new URL("../docs/MEDIA_BACKUP_MANIFEST.example.json", import.meta.url), "utf8"),
    readFile(new URL("../docs/OPERATIONS.md", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);
  assert.match(verifier, /readOnly: true/);
  assert.match(verifier, /PRAGMA integrity_check/);
  assert.match(verifier, /PRAGMA foreign_key_check/);
  assert.match(verifier, /push_subscriptions/);
  assert.match(verifier, /thumbnail_object_key/);
  assert.doesNotMatch(verifier, /\b(?:INSERT|UPDATE|DELETE|DROP|ALTER)\b/);
  assert.equal(JSON.parse(manifest).schema, "whisper-media-backup/v1");
  assert.match(operations, /opens the database read-only/i);
  assert.match(packageManifest, /"recovery:verify"/);
});
