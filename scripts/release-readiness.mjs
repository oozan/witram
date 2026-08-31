import { execFileSync } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const evidenceArgument = process.argv.find((value) => value.startsWith("--evidence="));
const enforce = process.argv.includes("--enforce");
const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const repositoryFiles = [
  "SECURITY.md", "docs/THREAT_MODEL.md", "docs/CRYPTOGRAPHY_REVIEW.md", "docs/PENETRATION_TEST_PLAN.md", "docs/INCIDENT_RESPONSE.md", "docs/OPERATIONS.md",
  "scripts/security-baseline.mjs", "scripts/security-probe.mjs", "scripts/production-smoke.mjs", "scripts/load-smoke.mjs", "scripts/verify-recovery.mjs", "scripts/incident-exercise.mjs",
  "drizzle/0008_kind_clint_barton.sql", ".github/workflows/security-review.yml", ".github/dependabot.yml",
];
const missingRepositoryFiles = [];
for (const path of repositoryFiles) try { await access(path); } catch { missingRepositoryFiles.push(path); }

const failures = [];
let evidence = null;
if (!evidenceArgument) failures.push("release evidence was not supplied");
else {
  try { evidence = JSON.parse(await readFile(resolve(evidenceArgument.slice("--evidence=".length)), "utf8")); } catch { failures.push("release evidence is unreadable or invalid JSON"); }
}
if (evidence) {
  if (evidence.schema !== "whisper-release-evidence/v1") failures.push("evidence schema");
  if (evidence.commit !== commit) failures.push("evidence commit does not match HEAD");
  try { if (new URL(evidence.deployedOrigin).protocol !== "https:") failures.push("deployed origin must use HTTPS"); } catch { failures.push("deployed origin"); }
  const accepted = (section) => section?.status === "accepted" && section?.reviewer && !/replace|placeholder/i.test(section.reviewer) && !Number.isNaN(Date.parse(section.completedAt));
  if (!accepted(evidence.independentCryptographyAudit) || !evidence.independentCryptographyAudit?.reportReference) failures.push("independent cryptography audit");
  if (!accepted(evidence.independentPenetrationTest) || !evidence.independentPenetrationTest?.reportReference || evidence.independentPenetrationTest?.criticalOpen !== 0 || evidence.independentPenetrationTest?.highOpen !== 0) failures.push("independent penetration test");
  const browser = evidence.browserAcceptance;
  if (browser?.status !== "passed" || !Array.isArray(browser?.browsers) || browser.browsers.length < 3 || browser?.syntheticAccounts < 2 || !browser?.mobileViewport || !browser?.desktopViewport || Number.isNaN(Date.parse(browser?.completedAt))) failures.push("multi-browser acceptance");
  const recovery = evidence.recoveryDrill;
  if (recovery?.status !== "passed" || !Number.isFinite(recovery?.achievedRpoMinutes) || !Number.isFinite(recovery?.achievedRtoMinutes) || Number.isNaN(Date.parse(recovery?.completedAt))) failures.push("recovery drill");
  const incident = evidence.incidentExercise;
  if (incident?.status !== "passed" || !incident?.scenario || !incident?.evidenceReference || Number.isNaN(Date.parse(incident?.completedAt))) failures.push("incident exercise");
  const monitoring = evidence.monitoring;
  if (monitoring?.status !== "passed" || [monitoring?.healthProbeAt, monitoring?.alertDeliveryAt, monitoring?.backupFreshnessAt, monitoring?.scheduledMaintenanceAt].some((date) => Number.isNaN(Date.parse(date)))) failures.push("monitoring and backup verification");
  const legal = evidence.legalApproval;
  if (legal?.status !== "approved" || !legal?.operatorIdentity || !legal?.privacyContact || !legal?.governingJurisdiction || Number.isNaN(Date.parse(legal?.completedAt)) || /replace|placeholder/i.test(`${legal?.operatorIdentity} ${legal?.privacyContact} ${legal?.governingJurisdiction}`)) failures.push("deployment legal approval");
}
if (missingRepositoryFiles.length) failures.push("repository controls are incomplete");

const productionReady = failures.length === 0;
process.stdout.write(`${JSON.stringify({ schema: "whisper-release-readiness/v1", generatedAt: new Date().toISOString(), commit, repositoryControlled: { result: missingRepositoryFiles.length ? "fail" : "pass", missingFiles: missingRepositoryFiles }, productionReady, externalEvidence: evidenceArgument ? "checked" : "not supplied", failures }, null, 2)}\n`);
if (enforce && !productionReady) process.exitCode = 1;
