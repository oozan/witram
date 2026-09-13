import { performance } from "node:perf_hooks";

const AUTHORIZATION = "I_HAVE_AUTHORIZATION";
const target = new URL(process.env.WHISPER_BASE_URL || "http://localhost:3000");
const local = ["localhost", "127.0.0.1", "::1"].includes(target.hostname);
if (!/^https?:$/.test(target.protocol)) throw new Error("WHISPER_BASE_URL must use HTTP(S)");
if (!local && process.env.SMOKE_TEST_AUTHORIZATION !== AUTHORIZATION) throw new Error(`Refusing a remote target without SMOKE_TEST_AUTHORIZATION=${AUTHORIZATION}`);

const bypass = process.env.VERCEL_AUTOMATION_BYPASS_SECRET;
const headers = { accept: "text/html,application/json" };
if (bypass) headers["x-vercel-protection-bypass"] = bypass;
const results = [];

async function check(name, path, validate) {
  const started = performance.now();
  try {
    const response = await fetch(new URL(path, target), { headers, redirect: "manual", signal: AbortSignal.timeout(10_000) });
    const body = (await response.text()).slice(0, 100_000);
    const outcome = validate(response, body);
    results.push({ name, path, status: response.status, durationMs: Math.round(performance.now() - started), ...outcome });
  } catch (error) {
    results.push({ name, path, result: "fail", detail: error instanceof Error ? error.message : "request failed" });
  }
}

await check("application shell", "/", (response, body) => {
  const csp = response.headers.get("content-security-policy") ?? "";
  const safe = response.status === 200 && /Whisper/i.test(body) && /frame-ancestors 'none'/.test(csp) && /script-src 'nonce-/.test(csp);
  return { result: safe ? "pass" : "fail", detail: safe ? "shell and nonce policy present" : "shell or browser policy missing" };
});
for (const [name, path, marker] of [["privacy policy", "/privacy", "Privacy Policy"], ["terms", "/terms", "Terms of Service"], ["security disclosure", "/security", "Independent review"]]) {
  await check(name, path, (response, body) => ({ result: response.status === 200 && body.includes(marker) ? "pass" : "fail", detail: `HTTP ${response.status}` }));
}
await check("storage health", "/api/health", (response, body) => {
  let payload;
  try { payload = JSON.parse(body); } catch { return { result: "fail", detail: "health response was not JSON" }; }
  const safe = !/(ciphertext|email|userId|filename|secret|token)/i.test(body);
  return { result: response.status === 200 && payload.status === "ok" && safe ? "pass" : "fail", detail: response.status === 200 ? `status=${payload.status}` : `HTTP ${response.status}` };
});

const failed = results.filter((result) => result.result !== "pass");
process.stdout.write(`${JSON.stringify({ schema: "whisper-production-smoke/v1", target: target.origin, generatedAt: new Date().toISOString(), result: failed.length ? "fail" : "pass", results }, null, 2)}\n`);
if (failed.length) process.exitCode = 1;
