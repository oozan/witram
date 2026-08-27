import { googleConfig, oauthCookie, randomToken, sha256 } from "../../_lib/auth";
import { database, initializeDatabase } from "../../_lib/social";

export async function GET(request: Request) {
  const configuration = googleConfig(request);
  if (!configuration) return Response.redirect(new URL("/?auth_error=google_not_configured", request.url), 303);
  await initializeDatabase();
  const state = randomToken();
  const verifier = randomToken(48);
  const nonce = randomToken();
  const challenge = await sha256(verifier);
  const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
  await database().prepare("INSERT INTO auth_oauth_states (state_hash, code_verifier, nonce, return_to, expires_at) VALUES (?, ?, ?, '/', ?)")
    .bind(await sha256(state), verifier, nonce, expiresAt).run();
  const authorize = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authorize.search = new URLSearchParams({
    client_id: configuration.clientId,
    redirect_uri: configuration.redirectUri,
    response_type: "code",
    scope: "openid email profile",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  }).toString();
  return new Response(null, { status: 302, headers: { location: authorize.toString(), "set-cookie": oauthCookie(state) } });
}
