import { clearOauthCookie, cookieValue, createSession, googleConfig, oauthCookie, sha256, verifyGoogleIdToken } from "../../../_lib/auth";
import { database, initializeDatabase } from "../../../_lib/social";
import { recordSecurityEvent } from "../../../_lib/safety";

type OauthState = { code_verifier: string; nonce: string; return_to: string; expires_at: string };

function fail(request: Request, code: string) {
  return new Response(null, { status: 303, headers: { location: new URL(`/?auth_error=${encodeURIComponent(code)}`, request.url).toString(), "set-cookie": clearOauthCookie() } });
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const state = url.searchParams.get("state") ?? "";
  const code = url.searchParams.get("code") ?? "";
  if (url.searchParams.has("error")) return fail(request, "google_cancelled");
  const configuration = googleConfig(request);
  const browserState = cookieValue(request, "__Host-whisper_oauth");
  if (!configuration || !state || !code || browserState !== state) return fail(request, "google_state_invalid");
  await initializeDatabase();
  const stateHash = await sha256(state);
  const stored = await database().prepare("SELECT code_verifier, nonce, return_to, expires_at FROM auth_oauth_states WHERE state_hash = ? LIMIT 1").bind(stateHash).first<OauthState>();
  await database().prepare("DELETE FROM auth_oauth_states WHERE state_hash = ?").bind(stateHash).run();
  if (!stored || stored.expires_at <= new Date().toISOString()) return fail(request, "google_state_expired");
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: configuration.clientId, client_secret: configuration.clientSecret, redirect_uri: configuration.redirectUri, grant_type: "authorization_code", code_verifier: stored.code_verifier }),
  });
  if (!tokenResponse.ok) return fail(request, "google_exchange_failed");
  const tokens = await tokenResponse.json() as { id_token?: string };
  if (!tokens.id_token) return fail(request, "google_identity_missing");
  try {
    const google = await verifyGoogleIdToken(tokens.id_token, { clientId: configuration.clientId, nonce: stored.nonce });
    const linked = await database().prepare("SELECT user_id FROM auth_oauth_accounts WHERE provider = 'google' AND provider_account_id = ? LIMIT 1").bind(google.subject).first<{ user_id: string }>();
    let userId = linked?.user_id;
    if (!userId) {
      const existing = await database().prepare("SELECT id FROM users WHERE email = ? LIMIT 1").bind(google.email).first<{ id: string }>();
      userId = existing?.id ?? `usr_${crypto.randomUUID()}`;
      if (!existing) await database().prepare("INSERT INTO users (id, email, display_name) VALUES (?, ?, ?)").bind(userId, google.email, google.displayName).run();
      await database().prepare("INSERT INTO auth_oauth_accounts (provider, provider_account_id, user_id) VALUES ('google', ?, ?)").bind(google.subject, userId).run();
    }
    await database().prepare("UPDATE users SET email = ?, display_name = COALESCE(display_name, ?), updated_at = ? WHERE id = ?").bind(google.email, google.displayName, new Date().toISOString(), userId).run();
    const session = await createSession(database(), userId, request);
    await recordSecurityEvent({ actorId: userId, category: "login_google", severity: "info", endpoint: "/api/auth/google/callback" });
    const headers = new Headers({ location: new URL(stored.return_to.startsWith("/") && !stored.return_to.startsWith("//") ? stored.return_to : "/", request.url).toString() });
    headers.append("set-cookie", session.cookie);
    headers.append("set-cookie", oauthCookie("", 0));
    return new Response(null, { status: 303, headers });
  } catch {
    return fail(request, "google_identity_invalid");
  }
}
