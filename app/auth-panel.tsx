"use client";

import { FormEvent, useState } from "react";

type AuthMode = "signin" | "register" | "recover";

const oauthErrors: Record<string, string> = {
  google_not_configured: "Google sign-in is not configured yet.",
  google_cancelled: "Google sign-in was cancelled.",
  google_state_invalid: "Google sign-in could not be verified. Please try again.",
  google_state_expired: "Google sign-in expired. Please try again.",
  google_exchange_failed: "Google could not complete sign-in.",
  google_identity_missing: "Google did not return an identity.",
  google_identity_invalid: "Google identity verification failed.",
};

export function AuthPanel({ authError, googleEnabled }: { authError?: string; googleEnabled: boolean }) {
  const [mode, setMode] = useState<AuthMode>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [challengeKind, setChallengeKind] = useState<"register" | "recover">("register");
  const [code, setCode] = useState("");
  const [error, setError] = useState(authError ? oauthErrors[authError] ?? "Sign-in could not be completed." : "");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError(""); setMessage("");
    const endpoint = mode === "signin" ? "/api/auth/email/login" : mode === "register" ? "/api/auth/email/register" : "/api/auth/password/request";
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password, displayName }),
      });
      const payload = await response.json() as { error?: string; challengeId?: string; message?: string };
      if (!response.ok) throw new Error(payload.error ?? "Authentication failed");
      if (payload.challengeId) {
        setChallengeId(payload.challengeId);
        setChallengeKind(mode === "recover" ? "recover" : "register");
        setMessage(payload.message ?? "Check your email for a verification code.");
      } else if (mode === "signin") window.location.assign("/");
      else setMessage(payload.message ?? "Check your email for the next step.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Authentication failed");
    } finally { setBusy(false); }
  }

  async function verify(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError("");
    try {
      const response = await fetch(challengeKind === "recover" ? "/api/auth/password/confirm" : "/api/auth/email/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ challengeId, code }),
      });
      const payload = await response.json() as { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Verification failed");
      window.location.assign("/");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Verification failed");
    } finally { setBusy(false); }
  }

  return <section className="auth-card">
    <span className="auth-mark">⌁</span>
    <p className="auth-eyebrow">Private by design</p>
    <h1>{challengeId ? challengeKind === "recover" ? "Reset your password" : "Verify your email" : mode === "recover" ? "Recover your account" : "Welcome to Whisper"}</h1>
    <p>{challengeId ? message : "Sign in to create your account, connect with people you trust, and access your encrypted conversations."}</p>

    {challengeId ? <form className="auth-form" onSubmit={verify}>
      <label htmlFor="verification-code">8-digit {challengeKind === "recover" ? "reset" : "verification"} code</label>
      <input id="verification-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{8}" maxLength={8} value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} required />
      {error && <p className="auth-error" role="alert">{error}</p>}
      <button disabled={busy || code.length !== 8}>{busy ? "Verifying…" : challengeKind === "recover" ? "Reset password and sign in" : "Verify and continue"}</button>
      <button className="auth-text-button" type="button" onClick={() => { setChallengeId(null); setCode(""); setError(""); }}>Start again</button>
    </form> : <>
      <div className="auth-tabs" role="tablist" aria-label="Email authentication">
        <button role="tab" aria-selected={mode === "signin"} onClick={() => { setMode("signin"); setError(""); }}>Sign in</button>
        <button role="tab" aria-selected={mode === "register"} onClick={() => { setMode("register"); setError(""); }}>Create account</button>
      </div>
      <form className="auth-form" onSubmit={submit}>
        {mode === "register" && <><label htmlFor="auth-name">Display name</label><input id="auth-name" autoComplete="name" minLength={2} maxLength={60} value={displayName} onChange={(event) => setDisplayName(event.target.value)} required /></>}
        <label htmlFor="auth-email">Email</label>
        <input id="auth-email" type="email" autoComplete="email" maxLength={254} value={email} onChange={(event) => setEmail(event.target.value)} required />
        <label htmlFor="auth-password">Password</label>
        <input id="auth-password" type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} minLength={12} maxLength={128} value={password} onChange={(event) => setPassword(event.target.value)} required />
        {mode !== "signin" && <small>Use at least 12 hard-to-guess characters and do not include your email name.</small>}
        {error && <p className="auth-error" role="alert">{error}</p>}
        {message && <p className="auth-success" role="status">{message}</p>}
        <button disabled={busy}>{busy ? "Please wait…" : mode === "signin" ? "Sign in with email" : mode === "register" ? "Email me a verification code" : "Email me a reset code"}</button>
        {mode === "signin" && <button className="auth-text-button" type="button" onClick={() => { setMode("recover"); setPassword(""); setError(""); setMessage(""); }}>Forgot password?</button>}
        {mode === "recover" && <button className="auth-text-button" type="button" onClick={() => { setMode("signin"); setPassword(""); setError(""); setMessage(""); }}>Back to sign in</button>}
      </form>
      {googleEnabled && <><div className="auth-divider"><span>or</span></div>
      <a className="google-auth-button" href="/api/auth/google"><span>G</span> Continue with Google</a></>}
    </>}
    <small>Whisper stores a protected password hash, never your password.{googleEnabled ? " Google authenticates you without sharing your Google password." : ""}</small>
    <nav className="auth-legal-links" aria-label="Legal"><a href="/security">Security</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a></nav>
  </section>;
}
