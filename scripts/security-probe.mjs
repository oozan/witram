import { performance } from "node:perf_hooks";

const AUTHORIZATION = "I_HAVE_AUTHORIZATION";
const targetArg = process.argv.find((value) => value.startsWith("--target="));
const target = new URL(targetArg?.slice(9) || process.env.SECURITY_TEST_TARGET || "http://localhost:3000");
const isLocal = ["localhost", "127.0.0.1", "::1"].includes(target.hostname);

if (process.env.SECURITY_TEST_AUTHORIZATION !== AUTHORIZATION) {
  throw new Error(`Refusing to probe without SECURITY_TEST_AUTHORIZATION=${AUTHORIZATION}`);
}
if (!isLocal && process.env.SECURITY_ALLOW_REMOTE !== "true") {
  throw new Error("Refusing a remote target without SECURITY_ALLOW_REMOTE=true; use an authorized staging deployment");
}
if (!/^https?:$/.test(target.protocol)) throw new Error("Only HTTP(S) targets are supported");

const auth = process.env.OAI_SITES_BYPASS_TOKEN;
const results = [];
async function probe(name, path, verify) {
  const url = new URL(path, target);
  const headers = { accept: "text/html,application/json" };
  if (auth) headers["OAI-Sites-Authorization"] = `Bearer ${auth}`;
  const started = performance.now();
  try {
    const response = await fetch(url, { headers, redirect: "manual", signal: AbortSignal.timeout(10_000) });
    const body = (await response.text()).slice(0, 2_048);
    const finding = verify(response, body);
    results.push({ name, path, status: response.status, durationMs: Math.round(performance.now() - started), ...finding });
  } catch (error) {
    results.push({ name, path, result: "fail", detail: error instanceof Error ? error.message : "request failed" });
  }
}

await probe("landing security headers", "/", (response) => {
  const required = ["x-content-type-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy"];
  const missing = required.filter((header) => !response.headers.get(header));
  if (target.protocol === "https:" && !response.headers.get("strict-transport-security")) missing.push("strict-transport-security");
  return { result: response.status < 500 && !missing.length ? "pass" : "fail", detail: missing.length ? `missing: ${missing.join(", ")}` : "baseline headers present" };
});
await probe("health disclosure boundary", "/api/health", (response, body) => ({
  result: response.status === 200 && !/(ciphertext|email|userId|filename|secret|token)/i.test(body) ? "pass" : "fail",
  detail: response.status === 200 ? "minimal readiness response" : `unexpected status ${response.status}`,
}));
await probe("operations authorization", "/api/operations", (response) => ({
  result: response.status === 401 || response.status === 403 || response.status === 404 || (response.status === 200 && Boolean(auth)) ? "pass" : "fail",
  detail: response.status === 200 ? "authorized operator response" : `access denied with ${response.status}`,
}));
await probe("invalid attachment reference", "/api/attachments/not-a-valid-identifier", (response) => ({
  result: [400, 401, 403, 404].includes(response.status) ? "pass" : "fail",
  detail: `rejected with ${response.status}`,
}));
await probe("security status page", "/security", (response, body) => ({
  result: response.status === 200 && /independent review pending/i.test(body) ? "pass" : "fail",
  detail: response.status === 200 ? "review status is publicly disclosed" : `unexpected status ${response.status}`,
}));

const failed = results.filter((item) => item.result !== "pass");
console.log(JSON.stringify({ schema: "whisper-authorized-probe/v1", target: target.origin, mode: "passive", generatedAt: new Date().toISOString(), result: failed.length ? "fail" : "pass", results }, null, 2));
if (failed.length) process.exitCode = 1;
