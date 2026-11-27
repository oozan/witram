// Behavioral tests for app/api/_lib/auth.ts.
// These execute the real module (Node strips the TypeScript types at load time)
// instead of pattern-matching its source, so they catch logic regressions.
import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, test } from "node:test";

import {
  clearSessionCookie,
  cookieValue,
  createEmailCode,
  createSession,
  emailCodeMatches,
  hashPassword,
  normalizeDisplayName,
  normalizeEmail,
  passwordValidationError,
  publicOrigin,
  randomNumericCode,
  randomToken,
  requireSameOrigin,
  revokeSession,
  sessionIdentity,
  sha256,
  verifyGoogleIdToken,
  verifyPassword,
} from "../app/api/_lib/auth.ts";

const SESSION_COOKIE = "__Host-whisper_session";
const savedEnv = { ...process.env };
const realFetch = globalThis.fetch;

afterEach(() => {
  process.env = { ...savedEnv };
  globalThis.fetch = realFetch;
});

const request = (url = "https://chat.example/api/x", headers = {}) => new Request(url, { headers });

describe("input normalization", () => {
  test("normalizeEmail trims, lowercases, and rejects malformed or oversized addresses", () => {
    assert.equal(normalizeEmail("  Alice@Example.COM "), "alice@example.com");
    assert.equal(normalizeEmail("no-at-sign"), null);
    assert.equal(normalizeEmail("a@b"), null);
    assert.equal(normalizeEmail("two words@example.com"), null);
    assert.equal(normalizeEmail(42), null);
    assert.equal(normalizeEmail(`${"a".repeat(250)}@x.io`), null);
  });

  test("normalizeDisplayName collapses whitespace, caps length, and falls back to the email name", () => {
    assert.equal(normalizeDisplayName("  Ada   Lovelace ", "ada@example.com"), "Ada Lovelace");
    assert.equal(normalizeDisplayName("x", "ada@example.com"), "ada");
    assert.equal(normalizeDisplayName(undefined, "ada@example.com"), "ada");
    assert.equal(normalizeDisplayName("n".repeat(100), "ada@example.com").length, 60);
  });

  test("passwordValidationError enforces length, common passwords, repetition, and email reuse", () => {
    assert.match(passwordValidationError("short"), /12–128/);
    assert.match(passwordValidationError("x".repeat(129)), /12–128/);
    assert.match(passwordValidationError("Password1234"), /less predictable/);
    assert.match(passwordValidationError("aaaaaaaaaaaa"), /less predictable/);
    assert.match(passwordValidationError("my-margaret-secret", "margaret@example.com"), /less predictable/);
    assert.equal(passwordValidationError("correct horse battery", "bob@example.com"), null);
  });
});

describe("password hashing", () => {
  test("hashes with a random salt and verifies only the original password", async () => {
    const first = await hashPassword("correct horse battery", undefined, 1_000);
    const second = await hashPassword("correct horse battery", undefined, 1_000);
    assert.notEqual(first.salt, second.salt, "each hash gets a fresh salt");
    assert.notEqual(first.hash, second.hash);

    const stored = { password_hash: first.hash, password_salt: first.salt, password_iterations: first.iterations };
    assert.equal(await verifyPassword("correct horse battery", stored), true);
    assert.equal(await verifyPassword("correct horse batterY", stored), false);
    assert.equal(await verifyPassword("", stored), false);
  });

  test("defaults to 600k PBKDF2 iterations", async () => {
    const result = await hashPassword("correct horse battery");
    assert.equal(result.iterations, 600_000);
  });

  test("verification uses the stored iteration count", async () => {
    const legacy = await hashPassword("legacy password!", undefined, 2_000);
    const stored = { password_hash: legacy.hash, password_salt: legacy.salt, password_iterations: 2_000 };
    assert.equal(await verifyPassword("legacy password!", stored), true);
    assert.equal(await verifyPassword("legacy password!", { ...stored, password_iterations: 2_001 }), false);
  });
});

describe("random values", () => {
  test("randomNumericCode always yields eight digits", () => {
    for (let index = 0; index < 500; index += 1) assert.match(randomNumericCode(), /^\d{8}$/);
  });

  test("randomToken is URL-safe and sized from its byte length", () => {
    const token = randomToken();
    assert.match(token, /^[A-Za-z0-9_-]+$/);
    assert.equal(token.length, 43);
    assert.equal(randomToken(16).length, 22);
    assert.notEqual(randomToken(), randomToken());
  });

  test("sha256 is deterministic base64url", async () => {
    assert.equal(await sha256("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
  });
});

describe("cookies", () => {
  test("cookieValue finds the named cookie and decodes it", () => {
    const req = request(undefined, { cookie: "a=1; __Host-whisper_session=tok%2Fen; b=x=y" });
    assert.equal(cookieValue(req, SESSION_COOKIE), "tok/en");
    assert.equal(cookieValue(req, "b"), "x=y");
    assert.equal(cookieValue(req, "missing"), null);
    assert.equal(cookieValue(request(), SESSION_COOKIE), null);
  });

  test("cookieValue treats a malformed percent-encoding as absent instead of throwing", () => {
    const req = request(undefined, { cookie: `${SESSION_COOKIE}=%E0%A4%A` });
    assert.equal(cookieValue(req, SESSION_COOKIE), null);
  });

  test("cleared session cookie is host-only, HttpOnly, Secure, and expired", () => {
    const cookie = clearSessionCookie();
    assert.match(cookie, /^__Host-whisper_session=;/);
    assert.match(cookie, /Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=0$/);
  });
});

// Minimal in-memory stand-in for the Turso adapter, covering only the
// statements the session helpers issue.
function fakeDatabase(users) {
  const sessions = new Map();
  const executed = [];
  const execute = (sql, args) => {
    executed.push(sql);
    if (sql.startsWith("INSERT INTO auth_sessions")) {
      const [tokenHash, userId, expiresAt, , , lastSeenAt] = args;
      sessions.set(tokenHash, { userId, expiresAt, lastSeenAt });
    } else if (sql.startsWith("DELETE FROM auth_sessions WHERE token_hash")) {
      sessions.delete(args[0]);
    } else if (sql.startsWith("UPDATE auth_sessions SET last_seen_at")) {
      sessions.get(args[1]).lastSeenAt = args[0];
    }
  };
  const statement = (sql, args = []) => ({
    sql,
    args,
    bind: (...values) => statement(sql, values),
    run: async () => { execute(sql, args); return { results: [], success: true, meta: { changes: 1 } }; },
    first: async () => {
      executed.push(sql);
      const session = sessions.get(args[0]);
      if (!session || session.expiresAt <= args[1]) return null;
      const user = users[session.userId];
      return { id: session.userId, email: user.email, display_name: user.displayName, last_seen_at: session.lastSeenAt };
    },
  });
  return {
    sessions,
    executed,
    prepare: (sql) => statement(sql),
    batch: async (statements) => statements.map((item) => { execute(item.sql, item.args); return { results: [], success: true, meta: { changes: 1 } }; }),
  };
}

describe("sessions", () => {
  const users = { "user-1": { email: "ada@example.com", displayName: null } };

  test("createSession stores only the token hash and returns a hardened cookie", async () => {
    const db = fakeDatabase(users);
    const { cookie, expiresAt } = await createSession(db, "user-1", request(undefined, { "user-agent": "test" }));
    const token = decodeURIComponent(cookie.match(/^__Host-whisper_session=([^;]+)/)[1]);

    assert.equal(db.sessions.size, 1);
    assert.ok(db.sessions.has(await sha256(token)), "stored key is the SHA-256 of the cookie token");
    assert.ok(!db.sessions.has(token), "raw token is never stored");
    assert.match(cookie, /HttpOnly; Secure; SameSite=Lax; Max-Age=2592000$/);
    const lifetimeDays = (new Date(expiresAt).getTime() - Date.now()) / 86_400_000;
    assert.ok(lifetimeDays > 29.9 && lifetimeDays <= 30);
    assert.ok(db.executed.some((sql) => sql.startsWith("DELETE FROM auth_sessions WHERE expires_at")), "expired sessions are swept");
  });

  test("sessionIdentity resolves a live session, falls back to the email name, and rejects unknown tokens", async () => {
    const db = fakeDatabase(users);
    const { cookie } = await createSession(db, "user-1", request());
    const token = cookie.match(/^__Host-whisper_session=([^;]+)/)[1];

    const identity = await sessionIdentity(db, request(undefined, { cookie: `${SESSION_COOKIE}=${token}` }));
    assert.deepEqual(identity, { userId: "user-1", email: "ada@example.com", displayName: "ada" });
    assert.equal(await sessionIdentity(db, request(undefined, { cookie: `${SESSION_COOKIE}=forged` })), null);
    assert.equal(await sessionIdentity(db, request()), null);
  });

  test("sessionIdentity returns null for a malformed session cookie", async () => {
    const db = fakeDatabase(users);
    assert.equal(await sessionIdentity(db, request(undefined, { cookie: `${SESSION_COOKIE}=%` })), null);
  });

  test("sessionIdentity refreshes last_seen_at only after 15 minutes of inactivity", async () => {
    const db = fakeDatabase(users);
    const { cookie } = await createSession(db, "user-1", request());
    const token = cookie.match(/^__Host-whisper_session=([^;]+)/)[1];
    const authed = request(undefined, { cookie: `${SESSION_COOKIE}=${token}` });
    const session = db.sessions.get(await sha256(decodeURIComponent(token)));

    await sessionIdentity(db, authed);
    assert.ok(!db.executed.some((sql) => sql.startsWith("UPDATE")), "fresh sessions are not rewritten");

    const stale = new Date(Date.now() - 16 * 60_000).toISOString();
    session.lastSeenAt = stale;
    await sessionIdentity(db, authed);
    assert.ok(session.lastSeenAt > stale, "stale sessions are touched");
  });

  test("revokeSession deletes the session so the cookie stops working", async () => {
    const db = fakeDatabase(users);
    const { cookie } = await createSession(db, "user-1", request());
    const authed = request(undefined, { cookie: cookie.split(";")[0] });

    await revokeSession(db, authed);
    assert.equal(db.sessions.size, 0);
    assert.equal(await sessionIdentity(db, authed), null);
  });
});

describe("request origin checks", () => {
  test("requireSameOrigin accepts same-origin and header-less requests", () => {
    assert.doesNotThrow(() => requireSameOrigin(request(undefined, { origin: "https://chat.example", "sec-fetch-site": "same-origin" })));
    assert.doesNotThrow(() => requireSameOrigin(request()));
  });

  test("requireSameOrigin rejects foreign origins and cross-site fetch metadata", () => {
    assert.throws(() => requireSameOrigin(request(undefined, { origin: "https://evil.example" })), /Cross-origin/);
    assert.throws(() => requireSameOrigin(request(undefined, { "sec-fetch-site": "cross-site" })), /Cross-origin/);
    assert.throws(() => requireSameOrigin(request(undefined, { "sec-fetch-site": "same-site" })), /Cross-origin/);
  });

  test("publicOrigin prefers the configured HTTPS origin and refuses plain HTTP", () => {
    delete process.env.AUTH_PUBLIC_ORIGIN;
    assert.equal(publicOrigin(request("http://internal:3000/x")), "http://internal:3000");
    process.env.AUTH_PUBLIC_ORIGIN = "https://chat.example/";
    assert.equal(publicOrigin(request("http://internal:3000/x")), "https://chat.example");
    process.env.AUTH_PUBLIC_ORIGIN = "http://localhost:3000";
    assert.equal(publicOrigin(request()), "http://localhost:3000");
    process.env.AUTH_PUBLIC_ORIGIN = "http://chat.example";
    assert.throws(() => publicOrigin(request()), /HTTPS/);
  });
});

describe("email verification codes", () => {
  test("codes are bound to the challenge and the server secret", async () => {
    process.env.AUTH_SECRET = "s".repeat(32);
    const expected = await createEmailCode("challenge-a", "12345678");
    assert.equal(await emailCodeMatches("challenge-a", "12345678", expected), true);
    assert.equal(await emailCodeMatches("challenge-a", "12345679", expected), false);
    assert.equal(await emailCodeMatches("challenge-b", "12345678", expected), false);

    process.env.AUTH_SECRET = "t".repeat(32);
    assert.equal(await emailCodeMatches("challenge-a", "12345678", expected), false);
  });

  test("a missing or short AUTH_SECRET fails closed", async () => {
    delete process.env.AUTH_SECRET;
    await assert.rejects(createEmailCode("c", "1"), /not configured/);
    process.env.AUTH_SECRET = "too-short";
    await assert.rejects(createEmailCode("c", "1"), /not configured/);
  });
});

describe("Google ID token verification", () => {
  const clientId = "client-123.apps.googleusercontent.com";
  const nonce = "nonce-abc";
  let keys;
  let jwk;

  const b64url = (value) => Buffer.from(value).toString("base64url");

  async function sign(payload, { header = { alg: "RS256", kid: "key-1" }, signingKey = keys.privateKey } = {}) {
    const unsigned = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signingKey, new TextEncoder().encode(unsigned));
    return `${unsigned}.${b64url(new Uint8Array(signature))}`;
  }

  const validClaims = (overrides = {}) => ({
    iss: "https://accounts.google.com",
    aud: clientId,
    exp: Math.floor(Date.now() / 1000) + 300,
    nonce,
    sub: "google-sub-1",
    email: "Ada@Example.com",
    email_verified: true,
    name: "Ada Lovelace",
    ...overrides,
  });

  beforeEach(async () => {
    const algorithm = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
    keys ??= await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    jwk ??= { ...(await crypto.subtle.exportKey("jwk", keys.publicKey)), kid: "key-1" };
    globalThis.fetch = async (url) => {
      assert.equal(String(url), "https://www.googleapis.com/oauth2/v3/certs");
      return Response.json({ keys: [jwk] });
    };
  });

  test("accepts a correctly signed token and normalizes the identity", async () => {
    const result = await verifyGoogleIdToken(await sign(validClaims()), { clientId, nonce });
    assert.deepEqual(result, { subject: "google-sub-1", email: "ada@example.com", displayName: "Ada Lovelace" });
  });

  test("accepts the legacy issuer and array audiences", async () => {
    const token = await sign(validClaims({ iss: "accounts.google.com", aud: ["other", clientId] }));
    assert.equal((await verifyGoogleIdToken(token, { clientId, nonce })).subject, "google-sub-1");
  });

  const rejections = [
    ["wrong nonce", { nonce: "replayed" }, /validation failed/],
    ["wrong audience", { aud: "someone-else" }, /validation failed/],
    ["wrong issuer", { iss: "https://evil.example" }, /validation failed/],
    ["expired token", { exp: Math.floor(Date.now() / 1000) - 1 }, /validation failed/],
    ["missing expiry", { exp: undefined }, /validation failed/],
    ["unverified email", { email_verified: false }, /did not verify/],
    ["invalid email", { email: "not-an-email" }, /invalid email/],
  ];
  for (const [name, overrides, pattern] of rejections) {
    test(`rejects a token with ${name}`, async () => {
      await assert.rejects(verifyGoogleIdToken(await sign(validClaims(overrides)), { clientId, nonce }), pattern);
    });
  }

  test("rejects a token signed by a different key", async () => {
    const other = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
    const token = await sign(validClaims(), { signingKey: other.privateKey });
    await assert.rejects(verifyGoogleIdToken(token, { clientId, nonce }), /validation failed/);
  });

  test("rejects a tampered payload", async () => {
    const [header, , signature] = (await sign(validClaims())).split(".");
    const forged = `${header}.${b64url(JSON.stringify(validClaims({ sub: "attacker" })))}.${signature}`;
    await assert.rejects(verifyGoogleIdToken(forged, { clientId, nonce }), /validation failed/);
  });

  test("rejects alg=none, unknown key ids, and malformed tokens before trusting claims", async () => {
    await assert.rejects(verifyGoogleIdToken(await sign(validClaims(), { header: { alg: "none", kid: "key-1" } }), { clientId, nonce }), /algorithm/);
    await assert.rejects(verifyGoogleIdToken(await sign(validClaims(), { header: { alg: "RS256", kid: "rotated" } }), { clientId, nonce }), /unknown/);
    await assert.rejects(verifyGoogleIdToken("a.b", { clientId, nonce }), /malformed/);
  });

  test("fails closed when Google's signing keys cannot be fetched", async () => {
    globalThis.fetch = async () => new Response("unavailable", { status: 503 });
    await assert.rejects(verifyGoogleIdToken(await sign(validClaims()), { clientId, nonce }), /unavailable/);
  });
});
