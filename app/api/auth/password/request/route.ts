import { createEmailCode, normalizeEmail, randomNumericCode, randomToken, requireSameOrigin, sendPasswordResetEmail, sha256 } from "../../../_lib/auth";
import { database, initializeDatabase, json } from "../../../_lib/social";
import { enforceRateLimit, recordSecurityEvent, safetyError } from "../../../_lib/safety";

const genericResponse = { message: "If this address has a password account, an 8-digit reset code is on its way." };

export async function POST(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Authentication request rejected" }, { status: 403 }); }
  if (Number(request.headers.get("content-length") ?? 0) > 3_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: { email?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const email = normalizeEmail(payload.email);
  if (!email) return json({ error: "Use a valid email address" }, { status: 400 });
  await initializeDatabase();
  const actor = await sha256(email);
  try { await enforceRateLimit({ actorKey: `auth-reset:${actor}`, scope: "auth-reset", endpoint: "/api/auth/password/request", limit: 4, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  const account = await database().prepare(
    "SELECT u.id FROM users u JOIN auth_credentials c ON c.user_id = u.id WHERE u.email = ? LIMIT 1",
  ).bind(email).first<{ id: string }>();
  if (!account) return json(genericResponse, { status: 202 });

  const challengeId = randomToken();
  const challengeHash = await sha256(challengeId);
  const code = randomNumericCode();
  const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
  let codeHash: string;
  try { codeHash = await createEmailCode(challengeHash, code); } catch (error) { return json({ error: error instanceof Error ? error.message : "Password recovery is unavailable" }, { status: 503 }); }
  await database().batch([
    database().prepare("DELETE FROM auth_password_reset_intents WHERE user_id = ? AND consumed_at IS NULL").bind(account.id),
    database().prepare(
      `INSERT INTO auth_password_reset_intents
        (challenge_hash, user_id, code_hash, expires_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(challengeHash, account.id, codeHash, expiresAt),
  ]);
  try {
    await sendPasswordResetEmail(email, code);
  } catch (error) {
    await database().prepare("DELETE FROM auth_password_reset_intents WHERE challenge_hash = ?").bind(challengeHash).run();
    return json({ error: error instanceof Error ? error.message : "Password reset email could not be sent" }, { status: 503 });
  }
  await recordSecurityEvent({ actorId: account.id, category: "password_reset_requested", severity: "info", endpoint: "/api/auth/password/request" });
  return json({ ...genericResponse, challengeId, expiresAt }, { status: 202 });
}
