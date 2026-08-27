import { createSession, emailCodeMatches, requireSameOrigin, sha256 } from "../../../_lib/auth";
import { database, initializeDatabase, json } from "../../../_lib/social";
import { enforceRateLimit, recordSecurityEvent, safetyError } from "../../../_lib/safety";

type Challenge = { email: string; display_name: string; password_hash: string; password_salt: string; password_iterations: number; code_hash: string; attempts: number; expires_at: string; consumed_at: string | null };

export async function POST(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Authentication request rejected" }, { status: 403 }); }
  let payload: { challengeId?: unknown; code?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const challengeId = typeof payload.challengeId === "string" ? payload.challengeId : "";
  const code = typeof payload.code === "string" ? payload.code.replace(/\s/g, "") : "";
  if (!challengeId || !/^\d{8}$/.test(code)) return json({ error: "Enter the 8-digit verification code" }, { status: 400 });
  await initializeDatabase();
  const challengeHash = await sha256(challengeId);
  try { await enforceRateLimit({ actorKey: `auth-verify:${challengeHash}`, scope: "auth-verify", endpoint: "/api/auth/email/verify", limit: 8, windowSeconds: 900 }); } catch (error) { return safetyError(error); }
  const challenge = await database().prepare("SELECT * FROM auth_email_challenges WHERE challenge_hash = ? LIMIT 1").bind(challengeHash).first<Challenge>();
  if (!challenge || challenge.consumed_at || challenge.expires_at <= new Date().toISOString() || challenge.attempts >= 5) return json({ error: "This verification request is invalid or expired" }, { status: 400 });
  if (!await emailCodeMatches(challengeHash, code, challenge.code_hash)) {
    await database().prepare("UPDATE auth_email_challenges SET attempts = attempts + 1 WHERE challenge_hash = ?").bind(challengeHash).run();
    return json({ error: "The verification code is incorrect" }, { status: 400 });
  }
  const userId = `usr_${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  try {
    await database().batch([
      database().prepare("INSERT INTO users (id, email, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)").bind(userId, challenge.email, challenge.display_name, now, now),
      database().prepare("INSERT INTO auth_credentials (user_id, password_hash, password_salt, password_iterations, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)").bind(userId, challenge.password_hash, challenge.password_salt, challenge.password_iterations, now, now),
      database().prepare("UPDATE auth_email_challenges SET consumed_at = ? WHERE challenge_hash = ?").bind(now, challengeHash),
    ]);
  } catch {
    return json({ error: "This email is already registered. Sign in instead." }, { status: 409 });
  }
  const session = await createSession(database(), userId, request);
  await recordSecurityEvent({ actorId: userId, category: "account_registered_email", severity: "info", endpoint: "/api/auth/email/verify" });
  return json({ account: { id: userId, email: challenge.email, displayName: challenge.display_name } }, { status: 201, headers: { "set-cookie": session.cookie } });
}
