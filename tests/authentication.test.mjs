import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("owns email credentials and stores only hardened password derivatives", async () => {
  const [auth, register, verify, login, schema, migration] = await Promise.all([
    source("../app/api/_lib/auth.ts"),
    source("../app/api/auth/email/register/route.ts"),
    source("../app/api/auth/email/verify/route.ts"),
    source("../app/api/auth/email/login/route.ts"),
    source("../db/schema.ts"),
    source("../drizzle/0006_crazy_hex.sql"),
  ]);

  assert.match(auth, /PBKDF2/);
  assert.match(auth, /600_000/);
  assert.match(auth, /getRandomValues\(new Uint8Array\(16\)\)/);
  assert.match(auth, /constantTimeEqual/);
  assert.match(register, /sendVerificationEmail/);
  assert.match(register, /randomNumericCode/);
  assert.match(verify, /attempts >= 5/);
  assert.match(verify, /consumed_at/);
  assert.match(login, /Email or password is incorrect/);
  assert.match(login, /auth-login/);
  assert.match(schema, /authCredentials/);
  assert.match(schema, /authEmailChallenges/);
  assert.match(migration, /CREATE TABLE `auth_credentials`/);
  assert.match(migration, /CREATE TABLE `auth_email_challenges`/);
});

test("uses hashed revocable sessions and hardened browser cookies", async () => {
  const [auth, social, logout, sessions, schema] = await Promise.all([
    source("../app/api/_lib/auth.ts"),
    source("../app/api/_lib/social.ts"),
    source("../app/api/auth/logout/route.ts"),
    source("../app/api/auth/sessions/route.ts"),
    source("../db/schema.ts"),
  ]);

  assert.match(auth, /__Host-whisper_session/);
  assert.match(auth, /HttpOnly; Secure; SameSite=Lax/);
  assert.match(auth, /tokenHash = await sha256\(token\)/);
  assert.match(auth, /DELETE FROM auth_sessions WHERE token_hash/);
  assert.match(social, /sessionIdentity/);
  assert.doesNotMatch(social, /oai-authenticated|x-whisper-user/);
  assert.match(social, /PRAGMA table_info\(\$\{table\}\)/);
  assert.match(social, /ensureColumns\(db, "users"/);
  assert.match(social, /ALTER TABLE users ADD COLUMN display_name TEXT/);
  assert.match(social, /ALTER TABLE users ADD COLUMN updated_at TEXT/);
  assert.match(social, /ALTER TABLE conversation_members ADD COLUMN role TEXT NOT NULL DEFAULT 'member'/);
  assert.match(social, /ALTER TABLE messages ADD COLUMN protocol TEXT NOT NULL DEFAULT 'legacy-aes-gcm'/);
  assert.match(social, /ALTER TABLE messages ADD COLUMN sender_device_id TEXT/);
  assert.match(logout, /requireSameOrigin/);
  assert.match(sessions, /token_hash <> \?/);
  assert.match(sessions, /DELETE FROM auth_sessions WHERE user_id = \?/);
  assert.match(sessions, /sessions_revoked/);
  assert.match(sessions, /clearSessionCookie/);
  assert.match(schema, /authSessions/);
});

test("supports one-time password recovery without account enumeration", async () => {
  const [auth, request, confirm, panel, schema] = await Promise.all([
    source("../app/api/_lib/auth.ts"),
    source("../app/api/auth/password/request/route.ts"),
    source("../app/api/auth/password/confirm/route.ts"),
    source("../app/auth-panel.tsx"),
    source("../db/schema.ts"),
  ]);

  assert.match(auth, /passwordValidationError/);
  assert.match(auth, /sendPasswordResetEmail/);
  assert.match(request, /genericResponse/);
  assert.match(request, /auth-reset/);
  assert.match(request, /auth_password_reset_intents/);
  assert.doesNotMatch(request, /hashPassword/);
  assert.match(confirm, /attempts >= 5/);
  assert.match(confirm, /passwordValidationError/);
  assert.match(confirm, /hashPassword/);
  assert.match(confirm, /auth_password_reset_intents/);
  assert.match(confirm, /DELETE FROM auth_sessions WHERE user_id/);
  assert.match(confirm, /password_reset_completed/);
  assert.match(panel, /Forgot password\?/);
  assert.match(panel, /We’ll email an 8-digit code/);
  assert.match(panel, /confirmPassword/);
  assert.match(schema, /authPasswordResets/);
});

test("implements Google OpenID Connect with PKCE, state, nonce, and signed token validation", async () => {
  const [auth, start, callback] = await Promise.all([
    source("../app/api/_lib/auth.ts"),
    source("../app/api/auth/google/route.ts"),
    source("../app/api/auth/google/callback/route.ts"),
  ]);

  assert.match(start, /code_challenge_method: "S256"/);
  assert.match(start, /state,/);
  assert.match(start, /nonce,/);
  assert.match(start, /openid email profile/);
  assert.match(callback, /browserState !== state/);
  assert.match(callback, /code_verifier/);
  assert.match(auth, /RS256/);
  assert.match(auth, /oauth2\/v3\/certs/);
  assert.match(auth, /payload\.aud/);
  assert.match(auth, /payload\.iss/);
  assert.match(auth, /payload\.email_verified !== true/);
  assert.doesNotMatch(callback, /refresh_token/);
});
