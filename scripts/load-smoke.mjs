import { performance } from "node:perf_hooks";

const AUTHORIZATION = "I_HAVE_AUTHORIZATION";
const target = new URL(process.env.WHISPER_BASE_URL || "http://localhost:3000");
const local = ["localhost", "127.0.0.1", "::1"].includes(target.hostname);
const requests = Math.min(1_000, Math.max(1, Number.parseInt(process.env.LOAD_REQUESTS || "100", 10)));
const concurrency = Math.min(25, Math.max(1, Number.parseInt(process.env.LOAD_CONCURRENCY || "10", 10)));
const maximumP95 = Math.max(50, Number.parseInt(process.env.LOAD_MAX_P95_MS || "1500", 10));
if (!/^https?:$/.test(target.protocol)) throw new Error("WHISPER_BASE_URL must use HTTP(S)");
if (!local && (process.env.LOAD_ALLOW_REMOTE !== "true" || process.env.LOAD_TEST_AUTHORIZATION !== AUTHORIZATION)) {
  throw new Error(`Refusing remote load without LOAD_ALLOW_REMOTE=true and LOAD_TEST_AUTHORIZATION=${AUTHORIZATION}`);
}

const bypass = process.env.OAI_SITES_BYPASS_TOKEN;
let issued = 0;
const samples = [];
async function worker() {
  while (issued < requests) {
    issued += 1;
    const started = performance.now();
    try {
      const headers = { accept: "application/json" };
      if (bypass) headers["OAI-Sites-Authorization"] = `Bearer ${bypass}`;
      const response = await fetch(new URL("/api/health", target), { headers, cache: "no-store", signal: AbortSignal.timeout(10_000) });
      const body = await response.json();
      samples.push({ ok: response.status === 200 && body.status === "ok", durationMs: performance.now() - started, status: response.status });
    } catch {
      samples.push({ ok: false, durationMs: performance.now() - started, status: 0 });
    }
  }
}

const started = performance.now();
await Promise.all(Array.from({ length: Math.min(concurrency, requests) }, () => worker()));
const durations = samples.map((sample) => sample.durationMs).sort((a, b) => a - b);
const percentile = (value) => Math.round(durations[Math.min(durations.length - 1, Math.ceil(durations.length * value) - 1)] ?? 0);
const failed = samples.filter((sample) => !sample.ok).length;
const result = failed === 0 && percentile(0.95) <= maximumP95 ? "pass" : "fail";
process.stdout.write(`${JSON.stringify({ schema: "whisper-bounded-load-smoke/v1", target: target.origin, endpoint: "/api/health", generatedAt: new Date().toISOString(), result, requests, concurrency, failed, durationMs: Math.round(performance.now() - started), latencyMs: { p50: percentile(0.5), p95: percentile(0.95), p99: percentile(0.99), maximum: Math.round(durations.at(-1) ?? 0) }, thresholds: { failed: 0, maximumP95 } }, null, 2)}\n`);
if (result !== "pass") process.exitCode = 1;
