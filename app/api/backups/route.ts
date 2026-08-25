import { database, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";

function validBase64(value: unknown, maximum: number) {
  return typeof value === "string" && value.length >= 4 && value.length <= maximum && /^[A-Za-z0-9+/=]+$/.test(value);
}

function decodedLength(value: unknown) {
  if (!validBase64(value, 256)) return 0;
  try { return Uint8Array.from(atob(value as string), (character) => character.charCodeAt(0)).length; } catch { return 0; }
}

export async function GET(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  await initializeDatabase();
  await registerIdentity(current);
  const backup = await database().prepare("SELECT ciphertext, iv, salt, version, source_device_id, created_at, updated_at FROM encrypted_backups WHERE user_id = ? LIMIT 1").bind(current.userId).first<{ ciphertext: string; iv: string; salt: string; version: string; source_device_id: string | null; created_at: string; updated_at: string }>();
  return json({ backup: backup ? { ciphertext: backup.ciphertext, iv: backup.iv, salt: backup.salt, version: Number(backup.version), sourceDeviceId: backup.source_device_id, createdAt: backup.created_at, updatedAt: backup.updated_at } : null });
}

export async function PUT(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 2_500_000) return json({ error: "Encrypted backup is too large" }, { status: 413 });
  let payload: Record<string, unknown>;
  try { payload = await request.json() as Record<string, unknown>; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const sourceDeviceId = typeof payload.sourceDeviceId === "string" ? payload.sourceDeviceId : "";
  if (!sourceDeviceId || !validBase64(payload.ciphertext, 2_300_000) || decodedLength(payload.iv) !== 12 || decodedLength(payload.salt) !== 32 || payload.version !== 1) return json({ error: "A valid encrypted backup is required" }, { status: 400 });
  await initializeDatabase();
  await registerIdentity(current);
  const db = database();
  if (!await db.prepare("SELECT 1 FROM devices WHERE id = ? AND user_id = ? AND active = '1' LIMIT 1").bind(sourceDeviceId, current.userId).first()) return json({ error: "An active source device is required" }, { status: 403 });
  const now = new Date().toISOString();
  await db.prepare(
    `INSERT INTO encrypted_backups (user_id, source_device_id, ciphertext, iv, salt, version, updated_at) VALUES (?, ?, ?, ?, ?, '1', ?)
     ON CONFLICT(user_id) DO UPDATE SET source_device_id = excluded.source_device_id, ciphertext = excluded.ciphertext, iv = excluded.iv, salt = excluded.salt, version = excluded.version, updated_at = excluded.updated_at`,
  ).bind(current.userId, sourceDeviceId, payload.ciphertext, payload.iv, payload.salt, now).run();
  return json({ backup: { updatedAt: now, version: 1 } });
}

export async function DELETE(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  await initializeDatabase();
  await registerIdentity(current);
  await database().prepare("DELETE FROM encrypted_backups WHERE user_id = ?").bind(current.userId).run();
  return json({ deleted: true });
}
