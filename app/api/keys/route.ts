import { database, type D1Result, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";

type StoredDevice = {
  id: string;
  name: string;
  identity_public_key: string;
  identity_signature: string;
  key_package: string;
  key_package_signature: string;
  key_package_version: string;
  updated_at: string;
};

const encoder = new TextEncoder();

function decodeBase64(value: unknown, maximum: number) {
  if (typeof value !== "string" || value.length < 4 || value.length > maximum || !/^[A-Za-z0-9+/=]+$/.test(value)) return null;
  try {
    return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function equalBytes(first: Uint8Array, second: Uint8Array) {
  if (first.length !== second.length) return false;
  let difference = 0;
  for (let index = 0; index < first.length; index += 1) difference |= first[index] ^ second[index];
  return difference === 0;
}

async function importEd25519(publicKey: Uint8Array) {
  const bytes = publicKey.buffer.slice(publicKey.byteOffset, publicKey.byteOffset + publicKey.byteLength) as ArrayBuffer;
  return crypto.subtle.importKey("raw", bytes, { name: "Ed25519" }, false, ["verify"]);
}

export async function GET(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  const requestedUserId = new URL(request.url).searchParams.get("userId")?.trim() || current.userId;

  await initializeDatabase();
  await registerIdentity(current);
  const db = database();
  if (requestedUserId !== current.userId && !await db.prepare(
    `SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ?
     AND NOT EXISTS (SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)) LIMIT 1`,
  ).bind(current.userId, requestedUserId, current.userId, requestedUserId, requestedUserId, current.userId).first()) {
    return json({ error: "Keys are available only for accepted, unblocked contacts" }, { status: 403 });
  }

  const user = await db.prepare("SELECT id, identity_public_key FROM users WHERE id = ? LIMIT 1").bind(requestedUserId).first<{ id: string; identity_public_key: string | null }>();
  if (!user?.identity_public_key) return json({ userId: requestedUserId, identityPublicKey: null, devices: [] });
  const devices = await db.prepare(
    `SELECT id, name, identity_public_key, identity_signature, key_package, key_package_signature, key_package_version, updated_at
     FROM devices WHERE user_id = ? AND active = '1' ORDER BY updated_at DESC LIMIT 20`,
  ).bind(requestedUserId).all() as D1Result<StoredDevice>;
  return json({
    userId: requestedUserId,
    identityPublicKey: user.identity_public_key,
    devices: (devices.results ?? []).map((device) => ({
      id: device.id,
      name: device.name,
      identityPublicKey: device.identity_public_key,
      identitySignature: device.identity_signature,
      keyPackage: device.key_package,
      keyPackageSignature: device.key_package_signature,
      keyPackageVersion: Number(device.key_package_version),
      updatedAt: device.updated_at,
    })),
  });
}

export async function POST(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 180_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: Record<string, unknown>;
  try {
    payload = await request.json() as Record<string, unknown>;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }

  const deviceId = typeof payload.deviceId === "string" && /^[a-f0-9-]{36}$/i.test(payload.deviceId) ? payload.deviceId : null;
  const name = typeof payload.name === "string" ? payload.name.trim().replace(/\s+/g, " ").slice(0, 60) : "";
  const userPublic = decodeBase64(payload.userIdentityPublicKey, 128);
  const devicePublic = decodeBase64(payload.deviceIdentityPublicKey, 128);
  const deviceSignature = decodeBase64(payload.deviceIdentitySignature, 256);
  const keyPackage = decodeBase64(payload.keyPackage, 120_000);
  const keyPackageSignature = decodeBase64(payload.keyPackageSignature, 256);
  const version = Number(payload.keyPackageVersion);
  if (!deviceId || name.length < 2 || userPublic?.length !== 32 || devicePublic?.length !== 32 || !deviceSignature || !keyPackage || !keyPackageSignature || !Number.isSafeInteger(version) || version < 1) {
    return json({ error: "A valid signed MLS device bundle is required" }, { status: 400 });
  }

  await initializeDatabase();
  await registerIdentity(current);
  const db = database();
  const storedUser = await db.prepare("SELECT identity_public_key FROM users WHERE id = ? LIMIT 1").bind(current.userId).first<{ identity_public_key: string | null }>();
  const storedUserKey = storedUser?.identity_public_key ? decodeBase64(storedUser.identity_public_key, 128) : null;
  if (storedUserKey && !equalBytes(storedUserKey, userPublic)) return json({ error: "This device does not possess the account identity key" }, { status: 409 });
  const storedDevice = await db.prepare("SELECT user_id, key_package_version FROM devices WHERE id = ? LIMIT 1").bind(deviceId).first<{ user_id: string; key_package_version: string }>();
  if (storedDevice?.user_id && storedDevice.user_id !== current.userId) return json({ error: "Device identifier is already registered" }, { status: 409 });
  if (storedDevice && version < Number(storedDevice.key_package_version)) return json({ error: "MLS key package versions cannot be rolled back" }, { status: 409 });

  const deviceBinding = encoder.encode(`whisper-device-v1:${current.userId}:${deviceId}:${payload.deviceIdentityPublicKey}`);
  const userVerifyKey = await importEd25519(userPublic);
  if (!await crypto.subtle.verify({ name: "Ed25519" }, userVerifyKey, deviceSignature, deviceBinding)) return json({ error: "Device identity signature is invalid" }, { status: 400 });
  const deviceVerifyKey = await importEd25519(devicePublic);
  if (!await crypto.subtle.verify({ name: "Ed25519" }, deviceVerifyKey, keyPackageSignature, keyPackage)) return json({ error: "MLS key package signature is invalid" }, { status: 400 });

  const now = new Date().toISOString();
  await db.batch([
    db.prepare("UPDATE users SET identity_public_key = COALESCE(identity_public_key, ?), updated_at = ? WHERE id = ?").bind(payload.userIdentityPublicKey, now, current.userId),
    db.prepare(
      `INSERT INTO devices (id, user_id, name, identity_public_key, identity_signature, key_package, key_package_signature, key_package_version, active, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, '1', ?)
       ON CONFLICT(id) DO UPDATE SET name = excluded.name, identity_public_key = excluded.identity_public_key,
       identity_signature = excluded.identity_signature, key_package = excluded.key_package,
       key_package_signature = excluded.key_package_signature, key_package_version = excluded.key_package_version,
       active = '1', updated_at = excluded.updated_at`,
    ).bind(deviceId, current.userId, name, payload.deviceIdentityPublicKey, payload.deviceIdentitySignature, payload.keyPackage, payload.keyPackageSignature, String(version), now),
  ]);
  return json({ device: { id: deviceId, keyPackageVersion: version, active: true } }, { status: 201 });
}

export async function DELETE(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  let payload: { deviceId?: unknown };
  try {
    payload = await request.json() as typeof payload;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const deviceId = typeof payload.deviceId === "string" ? payload.deviceId : "";
  await initializeDatabase();
  await registerIdentity(current);
  await database().prepare("UPDATE devices SET active = '0', updated_at = ? WHERE id = ? AND user_id = ?").bind(new Date().toISOString(), deviceId, current.userId).run();
  return json({ revoked: true });
}
