import { database, type D1Result, identity, initializeDatabase, json, registerIdentity } from "../../_lib/social";

type StoredWelcome = { id: string; conversation_id: string; sender_device_id: string; recipient_key_package_version: string; welcome: string; ratchet_tree: string; created_at: string };

function validBase64(value: unknown, maximum: number) {
  return typeof value === "string" && value.length >= 4 && value.length <= maximum && /^[A-Za-z0-9+/=]+$/.test(value);
}

export async function GET(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  const url = new URL(request.url);
  const conversationId = url.searchParams.get("conversationId")?.trim();
  const deviceId = url.searchParams.get("deviceId")?.trim();
  if (!conversationId || !deviceId) return json({ error: "Conversation and device are required" }, { status: 400 });
  await initializeDatabase();
  await registerIdentity(current);
  const db = database();
  if (!await db.prepare("SELECT 1 FROM devices WHERE id = ? AND user_id = ? AND active = '1' LIMIT 1").bind(deviceId, current.userId).first()) return json({ error: "Active device not found" }, { status: 403 });
  if (!await db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1").bind(conversationId, current.userId).first()) return json({ error: "Conversation membership is required" }, { status: 403 });
  const result = await db.prepare(
    `SELECT id, conversation_id, sender_device_id, recipient_key_package_version, welcome, ratchet_tree, created_at
     FROM mls_welcomes WHERE conversation_id = ? AND recipient_user_id = ? AND recipient_device_id = ? AND claimed_at IS NULL
     ORDER BY created_at ASC LIMIT 10`,
  ).bind(conversationId, current.userId, deviceId).all() as D1Result<StoredWelcome>;
  return json({ welcomes: (result.results ?? []).map((welcome) => ({ id: welcome.id, conversationId: welcome.conversation_id, senderDeviceId: welcome.sender_device_id, recipientKeyPackageVersion: Number(welcome.recipient_key_package_version), welcome: welcome.welcome, ratchetTree: welcome.ratchet_tree, createdAt: welcome.created_at })) });
}

export async function POST(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 500_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: Record<string, unknown>;
  try {
    payload = await request.json() as Record<string, unknown>;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const conversationId = typeof payload.conversationId === "string" ? payload.conversationId.trim() : "";
  const recipientUserId = typeof payload.recipientUserId === "string" ? payload.recipientUserId.trim() : "";
  const recipientDeviceId = typeof payload.recipientDeviceId === "string" ? payload.recipientDeviceId.trim() : "";
  const senderDeviceId = typeof payload.senderDeviceId === "string" ? payload.senderDeviceId.trim() : "";
  const recipientKeyPackageVersion = Number(payload.recipientKeyPackageVersion);
  if (!conversationId || !recipientUserId || !recipientDeviceId || !senderDeviceId || !Number.isSafeInteger(recipientKeyPackageVersion) || recipientKeyPackageVersion < 1 || !validBase64(payload.welcome, 300_000) || !validBase64(payload.ratchetTree, 180_000)) return json({ error: "A valid MLS welcome bundle is required" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  const db = database();
  if (!await db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1").bind(conversationId, current.userId).first()) return json({ error: "Conversation membership is required" }, { status: 403 });
  if (!await db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1").bind(conversationId, recipientUserId).first()) return json({ error: "Recipient is not a conversation member" }, { status: 403 });
  if (!await db.prepare("SELECT 1 FROM devices WHERE id = ? AND user_id = ? AND active = '1' LIMIT 1").bind(senderDeviceId, current.userId).first()) return json({ error: "Sender device is not active" }, { status: 403 });
  const recipientDevice = await db.prepare("SELECT key_package_version FROM devices WHERE id = ? AND user_id = ? AND active = '1' LIMIT 1").bind(recipientDeviceId, recipientUserId).first<{ key_package_version: string }>();
  if (!recipientDevice) return json({ error: "Recipient device is not active" }, { status: 403 });
  const pooledPackage = await db.prepare("SELECT 1 FROM device_key_packages WHERE device_id = ? AND version = ? AND consumed_at IS NULL LIMIT 1").bind(recipientDeviceId, String(recipientKeyPackageVersion)).first();
  if (!pooledPackage && Number(recipientDevice.key_package_version) !== recipientKeyPackageVersion) return json({ error: "Recipient key package is unavailable or already consumed" }, { status: 409 });
  if (await db.prepare("SELECT 1 FROM mls_welcomes WHERE recipient_device_id = ? AND recipient_key_package_version = ? LIMIT 1").bind(recipientDeviceId, String(recipientKeyPackageVersion)).first()) return json({ error: "Recipient key package has already been consumed" }, { status: 409 });

  const id = crypto.randomUUID();
  await db.batch([
    db.prepare(
      "INSERT INTO mls_welcomes (id, conversation_id, recipient_user_id, recipient_device_id, recipient_key_package_version, sender_device_id, welcome, ratchet_tree) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(id, conversationId, recipientUserId, recipientDeviceId, String(recipientKeyPackageVersion), senderDeviceId, payload.welcome, payload.ratchetTree),
    db.prepare("UPDATE device_key_packages SET consumed_at = ? WHERE device_id = ? AND version = ? AND consumed_at IS NULL").bind(new Date().toISOString(), recipientDeviceId, String(recipientKeyPackageVersion)),
  ]);
  return json({ welcome: { id } }, { status: 201 });
}

export async function PATCH(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  let payload: { welcomeId?: unknown; deviceId?: unknown };
  try {
    payload = await request.json() as typeof payload;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const welcomeId = typeof payload.welcomeId === "string" ? payload.welcomeId : "";
  const deviceId = typeof payload.deviceId === "string" ? payload.deviceId : "";
  await initializeDatabase();
  await registerIdentity(current);
  const result = await database().prepare(
    "UPDATE mls_welcomes SET claimed_at = ? WHERE id = ? AND recipient_user_id = ? AND recipient_device_id = ? AND claimed_at IS NULL",
  ).bind(new Date().toISOString(), welcomeId, current.userId, deviceId).run();
  if (!result.meta.changes) return json({ error: "Welcome was not found or already claimed" }, { status: 404 });
  return json({ claimed: true });
}
