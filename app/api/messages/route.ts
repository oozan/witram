import { database, type D1Result, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";

type StoredMessage = {
  id: string;
  conversation_id: string;
  sender_id: string;
  ciphertext: string;
  iv: string;
  created_at: string;
};

function isValidEncryptedField(value: unknown, maximum: number) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum && /^[A-Za-z0-9+/=]+$/.test(value);
}

export async function GET(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });

  const conversationId = new URL(request.url).searchParams.get("conversationId")?.trim();
  if (!conversationId || !/^[a-z0-9-]{1,80}$/i.test(conversationId)) return json({ error: "A valid conversationId is required" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  const db = database();
  const membership = await db.prepare(
    "SELECT 1 AS allowed FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1",
  ).bind(conversationId, current.userId).first();

  if (!membership) return json({ messages: [] });

  const result = await db.prepare(
    `SELECT id, conversation_id, sender_id, ciphertext, iv, created_at
     FROM messages WHERE conversation_id = ? ORDER BY created_at ASC, id ASC LIMIT 250`,
  ).bind(conversationId).all() as D1Result<StoredMessage>;

  return json({
    messages: (result.results ?? []).map((message) => ({
      id: message.id,
      ciphertext: message.ciphertext,
      iv: message.iv,
      createdAt: message.created_at,
      mine: message.sender_id === current.userId,
    })),
  });
}

export async function POST(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });

  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > 90_000) return json({ error: "Request body is too large" }, { status: 413 });

  let payload: { conversationId?: string; ciphertext?: string; iv?: string };
  try {
    payload = await request.json() as typeof payload;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const conversationId = payload.conversationId?.trim();

  if (!conversationId || !/^[a-z0-9-]{1,80}$/i.test(conversationId)) {
    return json({ error: "A valid conversationId is required" }, { status: 400 });
  }
  if (!isValidEncryptedField(payload.ciphertext, 64_000) || !isValidEncryptedField(payload.iv, 64)) {
    return json({ error: "A valid encrypted message payload is required" }, { status: 400 });
  }

  await initializeDatabase();
  await registerIdentity(current);
  const db = database();
  const membership = await db.prepare(
    "SELECT 1 AS allowed FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1",
  ).bind(conversationId, current.userId).first();
  if (!membership) return json({ error: "You are not a member of this conversation" }, { status: 403 });

  const blocked = await db.prepare(
    `SELECT 1 FROM conversation_members cm JOIN blocks b
       ON (b.blocker_id = ? AND b.blocked_id = cm.user_id)
       OR (b.blocked_id = ? AND b.blocker_id = cm.user_id)
     WHERE cm.conversation_id = ? AND cm.user_id != ? LIMIT 1`,
  ).bind(current.userId, current.userId, conversationId, current.userId).first();
  if (blocked) return json({ error: "Messages are disabled because a conversation member is blocked" }, { status: 403 });

  const id = crypto.randomUUID();
  await db.batch([
    db.prepare(
      "INSERT INTO messages (id, conversation_id, sender_id, ciphertext, iv) VALUES (?, ?, ?, ?, ?)",
    ).bind(id, conversationId, current.userId, payload.ciphertext, payload.iv),
  ]);

  return json({ message: { id, createdAt: new Date().toISOString() } }, { status: 201 });
}
