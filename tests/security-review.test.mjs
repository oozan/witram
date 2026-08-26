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
