import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

const databaseArgument = process.argv.find((value) => value.startsWith("--database="));
if (!databaseArgument) throw new Error("Usage: npm run recovery:verify -- --database=/absolute/path/to/restored.sqlite [--media-manifest=/absolute/path/to/manifest.json]");
const databasePath = resolve(databaseArgument.slice("--database=".length));
const manifestArgument = process.argv.find((value) => value.startsWith("--media-manifest="));
const requiredTables = [
  "users", "auth_credentials", "auth_sessions", "contacts", "contact_invitations", "conversations", "conversation_members", "messages",
  "devices", "device_key_packages", "device_link_sessions", "encrypted_backups", "mls_events", "mls_welcomes", "attachments", "blocks", "reports",
  "rate_limit_buckets", "security_events", "abuse_restrictions", "push_subscriptions",
];

const db = new DatabaseSync(databasePath, { readOnly: true });
try {
  const integrity = db.prepare("PRAGMA integrity_check").all().map((row) => String(row.integrity_check));
  const foreignKeys = db.prepare("PRAGMA foreign_key_check").all();
  const tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((row) => String(row.name)));
  const missingTables = requiredTables.filter((table) => !tables.has(table));
  const counts = {};
  for (const table of requiredTables.filter((table) => tables.has(table))) counts[table] = Number(db.prepare(`SELECT COUNT(*) AS total FROM "${table}"`).get().total);

  let media = { checked: false, requiredObjects: 0, manifestObjects: 0, missingObjects: 0, invalidHashes: 0 };
  if (manifestArgument) {
    const manifest = JSON.parse(await readFile(resolve(manifestArgument.slice("--media-manifest=".length)), "utf8"));
    if (!manifest || manifest.schema !== "whisper-media-backup/v1" || !Array.isArray(manifest.objects)) throw new Error("Media manifest must use whisper-media-backup/v1 and contain an objects array");
    const keys = new Set();
    let invalidHashes = 0;
    for (const object of manifest.objects) {
      if (!object || typeof object.key !== "string" || !/^[a-f0-9]{64}$/i.test(String(object.sha256)) || !Number.isSafeInteger(object.size) || object.size < 0) invalidHashes += 1;
      else keys.add(object.key);
    }
    const attachmentRows = tables.has("attachments") ? db.prepare("SELECT object_key, thumbnail_object_key FROM attachments WHERE status IN ('pending', 'ready')").all() : [];
    const requiredObjects = attachmentRows.flatMap((row) => [row.object_key, row.thumbnail_object_key]).filter(Boolean).map(String);
    media = { checked: true, requiredObjects: requiredObjects.length, manifestObjects: keys.size, missingObjects: requiredObjects.filter((key) => !keys.has(key)).length, invalidHashes };
  }

  const result = integrity.length === 1 && integrity[0] === "ok" && foreignKeys.length === 0 && missingTables.length === 0 && (!media.checked || (media.missingObjects === 0 && media.invalidHashes === 0)) ? "pass" : "fail";
  process.stdout.write(`${JSON.stringify({ schema: "whisper-recovery-verification/v1", generatedAt: new Date().toISOString(), result, database: { integrity, foreignKeyViolations: foreignKeys.length, missingTables, counts }, media }, null, 2)}\n`);
  if (result !== "pass") process.exitCode = 1;
} finally {
  db.close();
}
