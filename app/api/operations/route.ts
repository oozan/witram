import { database, identity, initializeDatabase, json } from "../_lib/social";
import { enforceRateLimit, isOperationsAdmin, recordSecurityEvent, safetyError } from "../_lib/safety";

async function authorize(request: Request) {
  const current = await identity(request);
  return current && isOperationsAdmin(current.userId) ? current : null;
}

export async function GET(request: Request) {
  const current = await authorize(request);
  if (!current) return json({ error: "Not found" }, { status: 404 });
  await initializeDatabase();
  try { await enforceRateLimit({ actorKey: `ops:${current.userId}`, actorId: current.userId, scope: "operations-read", endpoint: "/api/operations", limit: 60, windowSeconds: 3600 }); } catch (error) { return safetyError(error); }
  const db = database();
  const [events, reports, attachments, restrictions] = await Promise.all([
    db.prepare("SELECT severity, category, COUNT(*) AS count FROM security_events WHERE created_at >= datetime('now', '-1 day') GROUP BY severity, category ORDER BY count DESC LIMIT 30").all(),
    db.prepare("SELECT status, COUNT(*) AS count FROM reports GROUP BY status").all(),
    db.prepare("SELECT status, COUNT(*) AS count FROM attachments GROUP BY status").all(),
    db.prepare("SELECT COUNT(*) AS count FROM abuse_restrictions WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)").bind(new Date().toISOString()).first(),
  ]);
  return json({ period: "24h", securityEvents: events.results ?? [], reports: reports.results ?? [], attachments: attachments.results ?? [], activeRestrictions: Number((restrictions as { count?: number } | null)?.count ?? 0), generatedAt: new Date().toISOString() });
}

export async function POST(request: Request) {
  const current = await authorize(request);
  if (!current) return json({ error: "Not found" }, { status: 404 });
  if (Number(request.headers.get("content-length") ?? 0) > 4_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: { action?: unknown; userId?: unknown; scope?: unknown; durationHours?: unknown; reason?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const action = payload.action === "restrict" || payload.action === "unrestrict" ? payload.action : null;
  const userId = typeof payload.userId === "string" ? payload.userId.trim() : "";
  const scope = ["all", "messages", "media", "contacts"].includes(String(payload.scope)) ? String(payload.scope) : "all";
  const reason = typeof payload.reason === "string" ? payload.reason.trim().slice(0, 240) : "";
  const durationHours = Number(payload.durationHours);
  if (!action || !userId || (action === "restrict" && (!reason || !Number.isSafeInteger(durationHours) || durationHours < 1 || durationHours > 2160))) return json({ error: "A valid action, account, reason, and duration are required" }, { status: 400 });

  await initializeDatabase();
  try { await enforceRateLimit({ actorKey: `ops:${current.userId}`, actorId: current.userId, scope: "operations-write", endpoint: "/api/operations", limit: 30, windowSeconds: 3600 }); } catch (error) { return safetyError(error); }
  const db = database();
  if (!await db.prepare("SELECT 1 FROM users WHERE id = ? LIMIT 1").bind(userId).first()) return json({ error: "Account not found" }, { status: 404 });
  const now = new Date().toISOString();
  if (action === "unrestrict") {
    await db.prepare("UPDATE abuse_restrictions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(now, userId).run();
  } else {
    const expiresAt = new Date(Date.now() + durationHours * 3_600_000).toISOString();
    await db.prepare("INSERT INTO abuse_restrictions (id, user_id, scope, reason, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), userId, scope, reason, current.userId, expiresAt).run();
  }
  await recordSecurityEvent({ actorId: current.userId, category: `account_${action}ed`, severity: "warning", endpoint: "/api/operations", metadata: { targetUserId: userId, scope } });
  return json({ updated: true, action, userId, scope });
}
