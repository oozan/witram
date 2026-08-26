import { database, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";
import { enforceRateLimit, safetyError } from "../_lib/safety";

export async function POST(request: Request) {
  return updateBlock(request, true);
}

export async function DELETE(request: Request) {
  return updateBlock(request, false);
}

async function updateBlock(request: Request, shouldBlock: boolean) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 2_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: { userId?: unknown };
  try {
    payload = await request.json() as typeof payload;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const userId = typeof payload.userId === "string" ? payload.userId.trim() : "";
  if (!userId || userId === current.userId) return json({ error: "A valid account is required" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceRateLimit({ actorKey: `user:${current.userId}`, actorId: current.userId, scope: "block-actions", endpoint: "/api/blocks", limit: 40, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  const db = database();
  if (!await db.prepare("SELECT 1 FROM users WHERE id = ? LIMIT 1").bind(userId).first()) return json({ error: "Account not found" }, { status: 404 });
  if (!shouldBlock) {
    await db.prepare("DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?").bind(current.userId, userId).run();
    return json({ blocked: false });
  }
  await db.batch([
    db.prepare("INSERT OR IGNORE INTO blocks (blocker_id, blocked_id) VALUES (?, ?)").bind(current.userId, userId),
    db.prepare("DELETE FROM contacts WHERE (user_id = ? AND contact_id = ?) OR (user_id = ? AND contact_id = ?)").bind(current.userId, userId, userId, current.userId),
    db.prepare("UPDATE contact_invitations SET status = 'cancelled', responded_at = ? WHERE status = 'pending' AND ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))")
      .bind(new Date().toISOString(), current.userId, userId, userId, current.userId),
  ]);
  return json({ blocked: true });
}
