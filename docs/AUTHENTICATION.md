# Authentication setup

Whisper owns its account and session boundary; hosting-platform identity headers are ignored. Email accounts use D1, Web Crypto, secure cookies, and Resend; Google is an optional OpenID Connect provider that links only a Google-verified email address.

## How email authentication works

1. Registration validates the address and a 12–128 character password.
2. The Worker derives a salted password hash with PBKDF2-HMAC-SHA-256 at 600,000 iterations. The plaintext password is never stored.
3. Resend delivers an eight-digit code. D1 stores only a secret-keyed code hash and an expiring registration challenge.
4. After successful verification, the Worker creates the user and an opaque 256-bit session. D1 stores only its SHA-256 hash; the browser receives it in a `Secure`, `HttpOnly`, `SameSite=Lax` cookie.
5. Login performs a constant-work password check, uses a generic failure message, applies persistent rate limiting, and rotates the session token.
6. Password recovery accepts a new password before sending a one-time code. The new derivative stays server-side, completion revokes every prior session, and the browser receives a fresh session.

## Local configuration

Copy `.env.example` to `.env.local` and fill these values:

```dotenv
AUTH_SECRET=at-least-32-random-characters
AUTH_PUBLIC_ORIGIN=http://localhost:3000
RESEND_API_KEY=re_...
AUTH_EMAIL_FROM=Whisper <login@your-verified-domain.example>
GOOGLE_CLIENT_ID=optional-google-web-client-id
GOOGLE_CLIENT_SECRET=optional-google-web-client-secret
```

Create a strong local secret with `openssl rand -base64 48`. Keep every real value out of Git. `AUTH_EMAIL_FROM` must use a sender/domain verified in Resend.

## Google callback

For the current Sites URL, the exact authorized redirect URI is:

```text
https://whisper-private-chat.oozayranci.chatgpt.site/api/auth/google/callback
```

The application uses Authorization Code flow with PKCE S256, a one-time state value, an OpenID Connect nonce, and server-side Google ID-token signature and claim validation. It requests only `openid email profile` and does not retain Google access or refresh tokens.

## Production checklist

- Configure all environment values as deployment secrets, except the public origin.
- Use the exact public HTTPS origin in `AUTH_PUBLIC_ORIGIN`; do not add a trailing slash.
- Make the Site reachable to intended users after the app-owned login boundary is configured.
- Verify a Resend sender domain and test registration delivery, expiry, wrong-code attempts, and replay rejection.
- Configure Google consent and the exact redirect URI, then test accept, cancel, expired-state, and account-linking paths.
- Exercise password reset delivery, wrong-code limits, expiration, replay rejection, and automatic revocation of prior sessions.
- Monitor `login_failed`, `login_email`, `login_google`, and `account_registered_email` security events without recording passwords, codes, or tokens.
