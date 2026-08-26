import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";

const root = new URL("../", import.meta.url);
const failures = [];
const passes = [];

function check(name, condition, detail) {
  (condition ? passes : failures).push({ name, detail });
}

async function text(path) {
  return readFile(new URL(path, root), "utf8");
}

async function sourceFiles(directory = new URL("../app/", import.meta.url)) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const path = join(directory.pathname, entry.name);
    if (entry.isDirectory()) return sourceFiles(new URL(`file://${path}/`));
    return /\.(?:ts|tsx|mjs)$/.test(entry.name) ? [path] : [];
  }));
  return nested.flat();
}

const [manifestRaw, lockRaw, hosting, worker, mls, media, client, safety, operations] = await Promise.all([
  text("package.json"), text("package-lock.json"), text(".openai/hosting.json"), text("worker/index.ts"),
  text("app/mls-crypto.ts"), text("app/media-crypto.ts"), text("app/client-crypto.ts"),
  text("app/api/_lib/safety.ts"), text("app/api/operations/route.ts"),
]);
const manifest = JSON.parse(manifestRaw);
const lock = JSON.parse(lockRaw);
const dependencies = { ...manifest.dependencies, ...manifest.devDependencies };
const loose = Object.entries(dependencies).filter(([, version]) => !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version));

check("exact dependency versions", loose.length === 0, loose.length ? JSON.stringify(loose) : `${Object.keys(dependencies).length} direct dependencies pinned`);
check("npm lockfile v3", lock.lockfileVersion === 3, `lockfileVersion=${lock.lockfileVersion}`);
check("MLS implementation pinned", manifest.dependencies?.["ts-mls"] === "1.6.2", `ts-mls=${manifest.dependencies?.["ts-mls"]}`);
check("required storage bindings", /"d1"\s*:\s*"DB"/.test(hosting) && /"r2"\s*:\s*"MEDIA"/.test(hosting), "D1 DB and R2 MEDIA bindings");
check("browser security headers", ["x-content-type-options", "strict-transport-security", "permissions-policy", "cross-origin-opener-policy"].every((value) => worker.includes(value)), "Worker response header baseline");
check("MLS ciphersuite", mls.includes("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"), "RFC 9420 suite identifier");
check("link domain separation", mls.includes("whisper-device-link-v1") && mls.includes("additionalData"), "HKDF info plus AEAD AAD");
check("backup domain separation", mls.includes("whisper-encrypted-backup-v1") && mls.includes("additionalData"), "HKDF info plus account AAD");
check("media key and IV sizes", /getRandomValues\(new Uint8Array\(32\)\)/.test(media) && /getRandomValues\(new Uint8Array\(12\)\)/.test(media), "256-bit key and 96-bit nonce");
check("Saved Messages AEAD", client.includes("AES-GCM") && /getRandomValues\(new Uint8Array\(12\)\)/.test(client), "AES-GCM with random 96-bit nonce");
check("critical-event persistence", safety.includes("security_events") && safety.includes("ALERT_WEBHOOK_URL"), "durable event before optional alert delivery");
check("operator allowlist", safety.includes("OPS_ADMIN_USER_IDS") && operations.includes('return json({ error: "Not found" }, { status: 404 })'), "explicit fail-closed allowlist with concealed endpoint");

const files = await sourceFiles();
const source = (await Promise.all(files.map(async (path) => ({ path, value: await readFile(path, "utf8") }))));
const dangerous = source.flatMap(({ path, value }) => {
  const findings = [];
  if (/dangerouslySetInnerHTML/.test(value)) findings.push(`${relative(root.pathname, path)}: dangerouslySetInnerHTML`);
  if (/\beval\s*\(|\bnew Function\s*\(/.test(value)) findings.push(`${relative(root.pathname, path)}: dynamic code execution`);
  return findings;
});
check("no unsafe HTML or dynamic code sinks", dangerous.length === 0, dangerous.length ? dangerous.join(", ") : `${source.length} source files inspected`);

const report = {
  schema: "whisper-security-baseline/v1",
  generatedAt: new Date().toISOString(),
  result: failures.length ? "fail" : "pass",
  passes,
  failures,
};
console.log(JSON.stringify(report, null, 2));
if (failures.length) process.exitCode = 1;
