import { createSession, normalizeEmail, requireSameOrigin, sha256, validPassword, verifyPassword } from "../../../_lib/auth";
import { database, initializeDatabase, json } from "../../../_lib/social";
import { enforceRateLimit, recordSecurityEvent, safetyError } from "../../../_lib/safety";

type Credential = { id: string; email: string; display_name: string | null; password_hash: string; password_salt: string; password_iterations: number };

export async function POST(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Authentication request rejected" }, { status: 403 }); }
  let payload: { email?: unknown; password?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const email = normalizeEmail(payload.email);
  const password = typeof payload.password === "string" ? payload.password : "";
  if (!email || !validPassword(password)) return json({ error: "Email or password is incorrect" }, { status: 401 });
  await initializeDatabase();
  const actor = await sha256(email);
  try { await enforceRateLimit({ actorKey: `auth-login:${actor}`, scope: "auth-login", endpoint: "/api/auth/email/login", limit: 10, windowSeconds: 900 }); } catch (error) { return safetyError(error); }
  const credential = await database().prepare(
    `SELECT u.id, u.email, u.display_name, c.password_hash, c.password_salt, c.password_iterations
     FROM users u JOIN auth_credentials c ON c.user_id = u.id WHERE u.email = ? LIMIT 1`,
  ).bind(email).first<Credential>();
  const dummy = { password_hash: "X5RY3GbNu-NRTVhg10GHKOQwcEs8_0rSyW8Hp-qBmYY", password_salt: "AAECAwQFBgcICQoLDA0ODw", password_iterations: 600_000 };
  const valid = await verifyPassword(password, credential ?? dummy);
  if (!credential || !valid) {
    await recordSecurityEvent({ category: "login_failed", severity: "warning", endpoint: "/api/auth/email/login", metadata: { actor } });
    return json({ error: "Email or password is incorrect" }, { status: 401 });
  }
  const session = await createSession(database(), credential.id, request);
  await recordSecurityEvent({ actorId: credential.id, category: "login_email", severity: "info", endpoint: "/api/auth/email/login" });
  return json({ account: { id: credential.id, email: credential.email, displayName: credential.display_name ?? credential.email.split("@")[0] } }, { headers: { "set-cookie": session.cookie } });
}
