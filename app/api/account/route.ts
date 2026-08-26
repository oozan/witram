import { cleanDisplayName, database, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";
import { enforceRateLimit, safetyError } from "../_lib/safety";

export async function GET(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });

  await initializeDatabase();
  await registerIdentity(current);
  const profile = await database().prepare(
    "SELECT id, email, display_name, created_at FROM users WHERE id = ? LIMIT 1",
  ).bind(current.userId).first<{ id: string; email: string; display_name: string | null; created_at: string }>();

  return json({
    account: {
      id: profile?.id ?? current.userId,
      email: profile?.email ?? current.email,
      displayName: profile?.display_name ?? current.displayName,
      createdAt: profile?.created_at,
    },
  });
}

export async function PATCH(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 2_000) return json({ error: "Request body is too large" }, { status: 413 });

  let payload: { displayName?: unknown };
  try {
    payload = await request.json() as typeof payload;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const displayName = cleanDisplayName(payload.displayName);
  if (displayName.length < 2) return json({ error: "Display name must contain at least 2 characters" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceRateLimit({ actorKey: `user:${current.userId}`, actorId: current.userId, scope: "profile-updates", endpoint: "/api/account", limit: 10, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  await database().prepare("UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?")
    .bind(displayName, new Date().toISOString(), current.userId).run();
  return json({ account: { id: current.userId, email: current.email, displayName } });
}
