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
  const [auth, social, logout, schema] = await Promise.all([
    source("../app/api/_lib/auth.ts"),
    source("../app/api/_lib/social.ts"),
    source("../app/api/auth/logout/route.ts"),
    source("../db/schema.ts"),
  ]);

  assert.match(auth, /__Host-whisper_session/);
  assert.match(auth, /HttpOnly; Secure; SameSite=Lax/);
  assert.match(auth, /tokenHash = await sha256\(token\)/);
  assert.match(auth, /DELETE FROM auth_sessions WHERE token_hash/);
  assert.match(social, /sessionIdentity/);
  assert.doesNotMatch(social, /oai-authenticated|x-whisper-user/);
  assert.match(social, /PRAGMA table_info\(users\)/);
  assert.match(social, /ALTER TABLE users ADD COLUMN display_name TEXT/);
  assert.match(social, /ALTER TABLE users ADD COLUMN updated_at TEXT/);
  assert.match(logout, /requireSameOrigin/);
  assert.match(schema, /authSessions/);
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
