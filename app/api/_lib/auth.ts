import type { AuthenticatedIdentity } from "./social";
import type { WhisperDatabase } from "./platform";

const SESSION_COOKIE = "__Host-whisper_session";
const OAUTH_COOKIE = "__Host-whisper_oauth";
const SESSION_SECONDS = 30 * 24 * 60 * 60;
const PASSWORD_ITERATIONS = 600_000;
const encoder = new TextEncoder();

type AuthEnv = {
  AUTH_SECRET?: string;
  AUTH_PUBLIC_ORIGIN?: string;
  AUTH_EMAIL_FROM?: string;
  RESEND_API_KEY?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
};

export type AuthDatabase = WhisperDatabase;

function config() {
  return process.env as AuthEnv;
}

export function normalizeEmail(value: unknown) {
  const email = typeof value === "string" ? value.trim().toLowerCase() : "";
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

export function normalizeDisplayName(value: unknown, email: string) {
  const name = typeof value === "string" ? value.trim().replace(/\s+/g, " ").slice(0, 60) : "";
  return name.length >= 2 ? name : email.split("@")[0].slice(0, 60);
}

export function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 12 && value.length <= 128;
}

const commonPasswords = new Set([
  "123456789012", "adminadmin123", "iloveyou12345", "letmein123456", "password1234",
  "password12345", "password123456", "qwerty123456", "welcome12345", "whisper12345",
]);

export function passwordValidationError(value: unknown, email?: string | null) {
  if (!validPassword(value)) return "Use a password of 12–128 characters";
  const normalized = value.toLowerCase();
  const localPart = email?.split("@")[0]?.toLowerCase();
  if (commonPasswords.has(normalized) || /^(.)\1{11,}$/.test(value) || (localPart && localPart.length >= 4 && normalized.includes(localPart))) {
    return "Choose a less predictable password that does not contain your email name";
  }
  return null;
}

function bytesToBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function randomToken(size = 32) {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(size)));
}

export function randomNumericCode() {
  const maximum = 4_200_000_000;
  const sample = new Uint32Array(1);
  do crypto.getRandomValues(sample); while (sample[0] >= maximum);
  return (sample[0] % 100_000_000).toString().padStart(8, "0");
}

export async function sha256(value: string) {
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

async function authHmac(value: string) {
  const secret = config().AUTH_SECRET?.trim();
  if (!secret || secret.length < 32) throw new Error("Email authentication is not configured");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value))));
}

function constantTimeEqual(first: string, second: string) {
  const a = encoder.encode(first);
  const b = encoder.encode(second);
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}

export async function hashPassword(password: string, salt = crypto.getRandomValues(new Uint8Array(16)), iterations = PASSWORD_ITERATIONS) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const hash = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, 256));
  return { hash: bytesToBase64Url(hash), salt: bytesToBase64Url(salt), iterations };
}

export async function verifyPassword(password: string, stored: { password_hash: string; password_salt: string; password_iterations: number }) {
  const candidate = await hashPassword(password, base64UrlToBytes(stored.password_salt), stored.password_iterations);
  return constantTimeEqual(candidate.hash, stored.password_hash);
}

export function cookieValue(request: Request, name: string) {
  const cookie = request.headers.get("cookie") ?? "";
  for (const item of cookie.split(";")) {
    const [key, ...value] = item.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
  return null;
}

function secureCookie(name: string, value: string, maxAge: number) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function clearSessionCookie() {
  return secureCookie(SESSION_COOKIE, "", 0);
}

export function oauthCookie(value: string, maxAge = 600) {
  return secureCookie(OAUTH_COOKIE, value, maxAge);
}

export function clearOauthCookie() {
  return secureCookie(OAUTH_COOKIE, "", 0);
}

export async function createSession(db: AuthDatabase, userId: string, request: Request) {
  const token = randomToken();
  const tokenHash = await sha256(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_SECONDS * 1000).toISOString();
  const userAgent = (request.headers.get("user-agent") ?? "unknown").slice(0, 512);
  await db.batch([
    db.prepare("DELETE FROM auth_sessions WHERE expires_at <= ?").bind(now.toISOString()),
    db.prepare("DELETE FROM auth_oauth_states WHERE expires_at <= ?").bind(now.toISOString()),
    db.prepare("DELETE FROM auth_email_challenges WHERE expires_at <= ?").bind(now.toISOString()),
    db.prepare("DELETE FROM auth_password_resets WHERE expires_at <= ?").bind(now.toISOString()),
    db.prepare(
      "INSERT INTO auth_sessions (token_hash, user_id, expires_at, user_agent_hash, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).bind(tokenHash, userId, expiresAt, await sha256(userAgent), now.toISOString(), now.toISOString()),
  ]);
  return { cookie: secureCookie(SESSION_COOKIE, token, SESSION_SECONDS), expiresAt };
}

export async function revokeSession(db: AuthDatabase, request: Request) {
  const token = cookieValue(request, SESSION_COOKIE);
  if (token) await db.prepare("DELETE FROM auth_sessions WHERE token_hash = ?").bind(await sha256(token)).run();
}

export async function currentSessionHash(request: Request) {
  const token = cookieValue(request, SESSION_COOKIE);
  return token ? sha256(token) : null;
}

export async function sessionIdentity(db: AuthDatabase, request: Request): Promise<AuthenticatedIdentity | null> {
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token) return null;
  const current = await db.prepare(
    `SELECT u.id, u.email, u.display_name, s.last_seen_at FROM auth_sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ? LIMIT 1`,
  ).bind(await sha256(token), new Date().toISOString()).first<{ id: string; email: string; display_name: string | null; last_seen_at: string }>();
  if (!current?.email) return null;
  if (Date.now() - new Date(current.last_seen_at).getTime() > 15 * 60_000) {
    await db.prepare("UPDATE auth_sessions SET last_seen_at = ? WHERE token_hash = ?").bind(new Date().toISOString(), await sha256(token)).run();
  }
  return { userId: current.id, email: current.email, displayName: current.display_name ?? current.email.split("@")[0] };
}

export function requireSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  const site = request.headers.get("sec-fetch-site");
  if ((origin && origin !== new URL(request.url).origin) || (site && site !== "same-origin")) throw new Error("Cross-origin authentication request rejected");
}

export function publicOrigin(request: Request) {
  const configured = config().AUTH_PUBLIC_ORIGIN?.trim().replace(/\/$/, "");
  if (configured) {
    const url = new URL(configured);
    if (url.protocol !== "https:" && url.hostname !== "localhost") throw new Error("AUTH_PUBLIC_ORIGIN must use HTTPS");
    return url.origin;
  }
  return new URL(request.url).origin;
}

export function googleConfig(request: Request) {
  const clientId = config().GOOGLE_CLIENT_ID?.trim();
  const clientSecret = config().GOOGLE_CLIENT_SECRET?.trim();
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret, redirectUri: `${publicOrigin(request)}/api/auth/google/callback` };
}

export async function createEmailCode(challengeHash: string, code: string) {
  return authHmac(`whisper-email-code-v1:${challengeHash}:${code}`);
}

export async function emailCodeMatches(challengeHash: string, code: string, expected: string) {
  return constantTimeEqual(await createEmailCode(challengeHash, code), expected);
}

export async function sendVerificationEmail(email: string, code: string) {
  return sendAuthEmail(email, "Your Whisper verification code", `Your Whisper verification code is ${code}. It expires in 10 minutes. If you did not request this, ignore this email.`);
}

export async function sendPasswordResetEmail(email: string, code: string) {
  return sendAuthEmail(email, "Reset your Whisper password", `Your Whisper password reset code is ${code}. It expires in 10 minutes and can be used once. If you did not request this, you can ignore this email.`);
}

async function sendAuthEmail(email: string, subject: string, text: string) {
  const key = config().RESEND_API_KEY?.trim();
  const from = config().AUTH_EMAIL_FROM?.trim();
  if (!key || !from) throw new Error("Email delivery is not configured");
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({
      from,
      to: [email],
      subject,
      text,
    }),
  });
  if (!response.ok) throw new Error("Verification email could not be sent");
}

function decodeJwtPart(value: string) {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(value))) as Record<string, unknown>;
}

export async function verifyGoogleIdToken(idToken: string, expected: { clientId: string; nonce: string }) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Google identity token is malformed");
  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new Error("Google identity token algorithm is invalid");
  const certificates = await fetch("https://www.googleapis.com/oauth2/v3/certs", { headers: { accept: "application/json" } });
  if (!certificates.ok) throw new Error("Google signing keys are unavailable");
  const jwks = await certificates.json() as { keys?: Array<JsonWebKey & { kid?: string }> };
  const jwk = jwks.keys?.find((key) => key.kid === header.kid && key.kty === "RSA");
  if (!jwk) throw new Error("Google signing key is unknown");
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, base64UrlToBytes(parts[2]), encoder.encode(`${parts[0]}.${parts[1]}`));
  const now = Math.floor(Date.now() / 1000);
  const issuer = payload.iss === "https://accounts.google.com" || payload.iss === "accounts.google.com";
  const audience = payload.aud === expected.clientId || (Array.isArray(payload.aud) && payload.aud.includes(expected.clientId));
  if (!valid || !issuer || !audience || typeof payload.exp !== "number" || payload.exp <= now || payload.nonce !== expected.nonce) throw new Error("Google identity token validation failed");
  if (payload.email_verified !== true || typeof payload.email !== "string" || typeof payload.sub !== "string") throw new Error("Google did not verify this email address");
  const email = normalizeEmail(payload.email);
  if (!email) throw new Error("Google returned an invalid email address");
  return { subject: payload.sub, email, displayName: normalizeDisplayName(payload.name, email) };
}
