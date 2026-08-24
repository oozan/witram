import { database, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";

const categories = new Set(["spam", "harassment", "impersonation", "illegal", "other"]);

export async function POST(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 5_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: { userId?: unknown; conversationId?: unknown; category?: unknown; details?: unknown };
  try {
    payload = await request.json() as typeof payload;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const userId = typeof payload.userId === "string" ? payload.userId.trim() : "";
  const conversationId = typeof payload.conversationId === "string" ? payload.conversationId.trim() : null;
  const category = typeof payload.category === "string" && categories.has(payload.category) ? payload.category : null;
  const details = typeof payload.details === "string" ? payload.details.trim().slice(0, 1_000) : "";
  if (!userId || userId === current.userId || !category) return json({ error: "A valid account and report category are required" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  const db = database();
  if (conversationId && !await db.prepare("SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1").bind(conversationId, current.userId).first()) {
    return json({ error: "You cannot report a conversation you do not belong to" }, { status: 403 });
  }
  if (!await db.prepare("SELECT 1 FROM users WHERE id = ? LIMIT 1").bind(userId).first()) return json({ error: "Account not found" }, { status: 404 });
  const recent = await db.prepare(
    "SELECT 1 FROM reports WHERE reporter_id = ? AND reported_user_id = ? AND created_at >= datetime('now', '-1 day') LIMIT 1",
  ).bind(current.userId, userId).first();
  if (recent) return json({ error: "You already submitted a recent report for this account" }, { status: 429 });

  const id = crypto.randomUUID();
  await db.prepare(
    "INSERT INTO reports (id, reporter_id, reported_user_id, conversation_id, category, details) VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(id, current.userId, userId, conversationId, category, details || null).run();
  return json({ report: { id, status: "open" } }, { status: 201 });
}
