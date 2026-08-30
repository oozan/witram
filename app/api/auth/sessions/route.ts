import { clearSessionCookie, currentSessionHash, requireSameOrigin } from "../../_lib/auth";
import { database, identity, json } from "../../_lib/social";
import { enforceRateLimit, recordSecurityEvent, safetyError } from "../../_lib/safety";

type StoredSession = { token_hash: string; expires_at: string; user_agent_hash: string; created_at: string; last_seen_at: string };

export async function GET(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Authentication required" }, { status: 401 });
  const currentHash = await currentSessionHash(request);
  const sessions = await database().prepare(
    `SELECT token_hash, expires_at, user_agent_hash, created_at, last_seen_at
     FROM auth_sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC`,
  ).bind(current.userId, new Date().toISOString()).all<StoredSession>();
  return json({ sessions: (sessions.results ?? []).map((session) => ({
    id: session.token_hash,
    fingerprint: session.user_agent_hash.slice(0, 10),
    current: session.token_hash === currentHash,
    createdAt: session.created_at,
    lastSeenAt: session.last_seen_at,
    expiresAt: session.expires_at,
  })) });
}

export async function DELETE(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Authentication request rejected" }, { status: 403 }); }
  const current = await identity(request);
  if (!current) return json({ error: "Authentication required" }, { status: 401 });
  let payload: { action?: unknown; sessionId?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const action = payload.action;
  const sessionId = typeof payload.sessionId === "string" ? payload.sessionId : "";
  if (action !== "one" && action !== "others" && action !== "all") return json({ error: "Choose which sessions to revoke" }, { status: 400 });
  if (action === "one" && !/^[A-Za-z0-9_-]{43}$/.test(sessionId)) return json({ error: "Session identifier is invalid" }, { status: 400 });
  try { await enforceRateLimit({ actorKey: `session-control:${current.userId}`, actorId: current.userId, scope: "session-control", endpoint: "/api/auth/sessions", limit: 20, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }

  const currentHash = await currentSessionHash(request);
  const revokesCurrent = action === "all" || (action === "one" && sessionId === currentHash);
  const result = action === "all"
    ? await database().prepare("DELETE FROM auth_sessions WHERE user_id = ?").bind(current.userId).run()
    : action === "others"
      ? await database().prepare("DELETE FROM auth_sessions WHERE user_id = ? AND token_hash <> ?").bind(current.userId, currentHash).run()
      : await database().prepare("DELETE FROM auth_sessions WHERE user_id = ? AND token_hash = ?").bind(current.userId, sessionId).run();
  await recordSecurityEvent({ actorId: current.userId, category: "sessions_revoked", severity: action === "all" ? "warning" : "info", endpoint: "/api/auth/sessions", metadata: { action, count: result.meta.changes } });
  return json({ revoked: result.meta.changes, signedOut: revokesCurrent }, revokesCurrent ? { headers: { "set-cookie": clearSessionCookie() } } : undefined);
}
