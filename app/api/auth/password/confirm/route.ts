import { createSession, emailCodeMatches, hashPassword, passwordValidationError, requireSameOrigin, sha256 } from "../../../_lib/auth";
import { database, initializeDatabase, json } from "../../../_lib/social";
import { enforceRateLimit, recordSecurityEvent, safetyError } from "../../../_lib/safety";

type Reset = { user_id: string; code_hash: string; attempts: number; expires_at: string; consumed_at: string | null };

export async function POST(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Authentication request rejected" }, { status: 403 }); }
  let payload: { challengeId?: unknown; code?: unknown; password?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const challengeId = typeof payload.challengeId === "string" ? payload.challengeId : "";
  const code = typeof payload.code === "string" ? payload.code.replace(/\s/g, "") : "";
  if (!challengeId || !/^\d{8}$/.test(code)) return json({ error: "Enter the 8-digit reset code" }, { status: 400 });
  const passwordError = passwordValidationError(payload.password, "");
  if (passwordError) return json({ error: passwordError }, { status: 400 });
  await initializeDatabase();
  const challengeHash = await sha256(challengeId);
  try { await enforceRateLimit({ actorKey: `auth-reset-confirm:${challengeHash}`, scope: "auth-reset-confirm", endpoint: "/api/auth/password/confirm", limit: 8, windowSeconds: 900 }); } catch (error) { return safetyError(error); }
  const reset = await database().prepare("SELECT * FROM auth_password_reset_intents WHERE challenge_hash = ? LIMIT 1").bind(challengeHash).first<Reset>();
  const now = new Date().toISOString();
  if (!reset || reset.consumed_at || reset.expires_at <= now || reset.attempts >= 5) return json({ error: "This password reset is invalid or expired" }, { status: 400 });
  if (!await emailCodeMatches(challengeHash, code, reset.code_hash)) {
    await database().prepare("UPDATE auth_password_reset_intents SET attempts = attempts + 1 WHERE challenge_hash = ?").bind(challengeHash).run();
    return json({ error: "The reset code is incorrect" }, { status: 400 });
  }
  const password = await hashPassword(payload.password as string);
  const updated = await database().prepare(
    `UPDATE auth_credentials SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ?
     WHERE user_id = ? AND EXISTS (
       SELECT 1 FROM auth_password_reset_intents WHERE challenge_hash = ? AND consumed_at IS NULL AND expires_at > ?
     )`,
  ).bind(password.hash, password.salt, password.iterations, now, reset.user_id, challengeHash, now).run();
  if (!updated.success || updated.meta.changes !== 1) return json({ error: "This password reset is invalid or expired" }, { status: 400 });
  await database().batch([
    database().prepare("DELETE FROM auth_sessions WHERE user_id = ?").bind(reset.user_id),
    database().prepare("UPDATE auth_password_reset_intents SET consumed_at = ? WHERE challenge_hash = ?").bind(now, challengeHash),
    database().prepare("DELETE FROM auth_password_reset_intents WHERE user_id = ? AND challenge_hash <> ?").bind(reset.user_id, challengeHash),
  ]);
  const session = await createSession(database(), reset.user_id, request);
  await recordSecurityEvent({ actorId: reset.user_id, category: "password_reset_completed", severity: "warning", endpoint: "/api/auth/password/confirm" });
  return json({ message: "Password updated. Other sessions were signed out." }, { headers: { "set-cookie": session.cookie } });
}
