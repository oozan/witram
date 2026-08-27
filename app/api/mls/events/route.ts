import { database, type D1Result, identity, initializeDatabase, json, registerIdentity } from "../../_lib/social";
import { enforceWriteSafety, safetyError } from "../../_lib/safety";

type StoredEvent = { id: string; sender_device_id: string; kind: "commit"; payload: string; epoch: string; created_at: string };

export async function GET(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  const url = new URL(request.url);
  const conversationId = url.searchParams.get("conversationId")?.trim();
  const after = url.searchParams.get("after")?.trim();
  if (!conversationId) return json({ error: "Conversation is required" }, { status: 400 });
  await initializeDatabase();
  await registerIdentity(current);
  const db = database();
  if (!await db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1").bind(conversationId, current.userId).first()) return json({ error: "Conversation membership is required" }, { status: 403 });
  const result = after
    ? await db.prepare(`SELECT id, sender_device_id, kind, payload, epoch, created_at FROM mls_events WHERE conversation_id = ? AND (created_at > (SELECT created_at FROM mls_events WHERE id = ?) OR (created_at = (SELECT created_at FROM mls_events WHERE id = ?) AND id > ?)) ORDER BY created_at ASC, id ASC LIMIT 100`).bind(conversationId, after, after, after).all() as D1Result<StoredEvent>
    : await db.prepare("SELECT id, sender_device_id, kind, payload, epoch, created_at FROM mls_events WHERE conversation_id = ? ORDER BY created_at ASC, id ASC LIMIT 100").bind(conversationId).all() as D1Result<StoredEvent>;
  return json({ events: (result.results ?? []).map((event) => ({ id: event.id, senderDeviceId: event.sender_device_id, kind: event.kind, payload: event.payload, epoch: Number(event.epoch), createdAt: event.created_at })) });
}

export async function POST(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 300_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: Record<string, unknown>;
  try {
    payload = await request.json() as Record<string, unknown>;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const conversationId = typeof payload.conversationId === "string" ? payload.conversationId.trim() : "";
  const senderDeviceId = typeof payload.senderDeviceId === "string" ? payload.senderDeviceId.trim() : "";
  const eventPayload = typeof payload.payload === "string" && payload.payload.length <= 250_000 && /^[A-Za-z0-9+/=]+$/.test(payload.payload) ? payload.payload : "";
  const epoch = Number(payload.epoch);
  if (!conversationId || !senderDeviceId || !eventPayload || !Number.isSafeInteger(epoch) || epoch < 1 || payload.kind !== "commit") return json({ error: "A valid MLS commit is required" }, { status: 400 });
  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceWriteSafety({ userId: current.userId, scope: "mls-commits", restriction: "messages", endpoint: "/api/mls/events", limit: 120, windowSeconds: 3_600, cost: Math.ceil(Number(request.headers.get("content-length") ?? 0) / 16_384), costLimit: 600 }); } catch (error) { return safetyError(error); }
  const db = database();
  if (!await db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1").bind(conversationId, current.userId).first()) return json({ error: "Conversation membership is required" }, { status: 403 });
  if (!await db.prepare("SELECT 1 FROM devices WHERE id = ? AND user_id = ? AND active = '1' LIMIT 1").bind(senderDeviceId, current.userId).first()) return json({ error: "Sender device is not active" }, { status: 403 });
  const id = crypto.randomUUID();
  await db.prepare("INSERT INTO mls_events (id, conversation_id, sender_device_id, kind, payload, epoch) VALUES (?, ?, ?, 'commit', ?, ?)").bind(id, conversationId, senderDeviceId, eventPayload, String(epoch)).run();
  return json({ event: { id, epoch } }, { status: 201 });
}
