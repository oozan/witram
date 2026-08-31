import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const scenarios = {
  xss: ["detect the affected release", "contain client execution", "preserve CSP and deployment evidence", "assess key and plaintext exposure"],
  account_takeover: ["revoke account sessions", "preserve authentication evidence", "assess linked devices", "notify the account owner safely"],
  data_loss: ["stop inconsistent writes", "select a recovery point", "restore in isolation", "measure achieved RPO and RTO"],
  crypto_vulnerability: ["identify affected protocol versions", "pause unsafe messaging", "obtain independent cryptographic guidance", "plan compatible remediation"],
  provider_outage: ["confirm provider scope", "activate service communication", "protect queued operations", "validate recovery before resolution"],
};
const scenarioArgument = process.argv.find((value) => value.startsWith("--scenario="));
const scenario = scenarioArgument?.slice("--scenario=".length);
if (!scenario || !scenarios[scenario]) throw new Error(`Choose --scenario=${Object.keys(scenarios).join("|")}`);
const evidenceArgument = process.argv.find((value) => value.startsWith("--evidence="));

if (!evidenceArgument) {
  process.stdout.write(`${JSON.stringify({ schema: "whisper-incident-exercise-plan/v1", status: "planned", scenario, objectives: scenarios[scenario], requiredRoles: ["incident_commander", "security_lead", "privacy_lead"], instructions: "Run the tabletop from docs/INCIDENT_RESPONSE.md, record decisions and timestamps in the evidence schema, then rerun with --evidence=/absolute/path/to/evidence.json. A generated plan is not a completed exercise." }, null, 2)}\n`);
  process.exit(0);
}

const evidence = JSON.parse(await readFile(resolve(evidenceArgument.slice("--evidence=".length)), "utf8"));
const failures = [];
if (evidence?.schema !== "whisper-incident-exercise/v1") failures.push("schema");
if (evidence?.scenario !== scenario) failures.push("scenario");
if (!/^[a-f0-9]{7,40}$/i.test(String(evidence?.commit ?? "")) || /^0+$/.test(String(evidence?.commit ?? ""))) failures.push("commit");
const roles = new Set(Array.isArray(evidence?.participants) ? evidence.participants.map((participant) => participant?.role) : []);
for (const role of ["incident_commander", "security_lead", "privacy_lead"]) if (!roles.has(role)) failures.push(`participant:${role}`);
if (!Array.isArray(evidence?.participants) || evidence.participants.some((participant) => !participant?.name || /replace|placeholder/i.test(participant.name))) failures.push("participant names");
const approvals = new Set(Array.isArray(evidence?.approvedBy) ? evidence.approvedBy : []);
for (const role of ["incident_commander", "security_lead", "privacy_lead"]) if (!approvals.has(role)) failures.push(`approval:${role}`);
const timestamps = ["heldAt", "detectedAt", "declaredAt", "containedAt", "recoveredAt"];
const times = timestamps.map((field) => Date.parse(evidence?.[field]));
if (times.some(Number.isNaN) || times.some((time, index) => index > 0 && time < times[index - 1])) failures.push("timeline");
if (!Array.isArray(evidence?.decisions) || evidence.decisions.length < 1 || evidence.decisions.some((decision) => /replace|placeholder/i.test(String(decision)))) failures.push("decisions");
if (!Array.isArray(evidence?.gaps)) failures.push("gaps");
else if (evidence.gaps.some((gap) => !gap?.description || !gap?.owner || /replace|named owner|placeholder/i.test(`${gap.description} ${gap.owner}`) || Number.isNaN(Date.parse(gap?.dueAt)))) failures.push("gap ownership");
const result = failures.length ? "fail" : "pass";
process.stdout.write(`${JSON.stringify({ schema: "whisper-incident-exercise-validation/v1", generatedAt: new Date().toISOString(), result, scenario, reviewedCommit: evidence?.commit ?? null, participantCount: Array.isArray(evidence?.participants) ? evidence.participants.length : 0, decisionCount: Array.isArray(evidence?.decisions) ? evidence.decisions.length : 0, gapCount: Array.isArray(evidence?.gaps) ? evidence.gaps.length : 0, failures }, null, 2)}\n`);
if (failures.length) process.exitCode = 1;
