import { createEmailCode, hashPassword, normalizeDisplayName, normalizeEmail, passwordValidationError, randomNumericCode, randomToken, requireSameOrigin, sendVerificationEmail, sha256 } from "../../../_lib/auth";
import { database, initializeDatabase, json } from "../../../_lib/social";
import { enforceRateLimit, safetyError } from "../../../_lib/safety";

export async function POST(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Authentication request rejected" }, { status: 403 }); }
  if (Number(request.headers.get("content-length") ?? 0) > 3_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: { email?: unknown; password?: unknown; displayName?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const email = normalizeEmail(payload.email);
  if (!email) return json({ error: "Use a valid email address" }, { status: 400 });
  const passwordError = passwordValidationError(payload.password, email);
  if (passwordError) return json({ error: passwordError }, { status: 400 });
  const displayName = normalizeDisplayName(payload.displayName, email);
  await initializeDatabase();
  const actor = await sha256(email);
  try { await enforceRateLimit({ actorKey: `auth-register:${actor}`, scope: "auth-register", endpoint: "/api/auth/email/register", limit: 4, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  const existing = await database().prepare("SELECT 1 FROM users WHERE email = ? LIMIT 1").bind(email).first();
  if (existing) return json({ error: "This email is already registered. Sign in or use its original provider." }, { status: 409 });

  const challengeId = randomToken();
  const challengeHash = await sha256(challengeId);
  const code = randomNumericCode();
  const password = await hashPassword(payload.password as string);
  const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
  let codeHash: string;
  try { codeHash = await createEmailCode(challengeHash, code); } catch (error) { return json({ error: error instanceof Error ? error.message : "Email authentication is unavailable" }, { status: 503 }); }
  await database().prepare(
    `INSERT INTO auth_email_challenges
      (challenge_hash, email, display_name, password_hash, password_salt, password_iterations, code_hash, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(challengeHash, email, displayName, password.hash, password.salt, password.iterations, codeHash, expiresAt).run();
  try {
    await sendVerificationEmail(email, code);
  } catch (error) {
    await database().prepare("DELETE FROM auth_email_challenges WHERE challenge_hash = ?").bind(challengeHash).run();
    return json({ error: error instanceof Error ? error.message : "Verification email could not be sent" }, { status: 503 });
  }
  return json({ challengeId, expiresAt, message: "Check your email for the 8-digit verification code." }, { status: 202 });
}
