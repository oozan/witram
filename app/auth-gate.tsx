"use client";

import { useEffect, useState } from "react";

import { AuthPanel } from "./auth-panel";
import { ChatApp } from "./chat-app";

type Account = { id: string; email: string; displayName: string };

export function AuthGate({ hasSessionHint, authError }: { hasSessionHint: boolean; authError?: string }) {
  const [account, setAccount] = useState<Account | null>(null);
  const [checking, setChecking] = useState(hasSessionHint);

  useEffect(() => {
    if (!hasSessionHint) return;
    let active = true;
    void fetch("/api/account", { headers: { accept: "application/json" }, cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("Session expired");
        return response.json() as Promise<{ account: Account }>;
      })
      .then((payload) => { if (active) setAccount(payload.account); })
      .catch(() => { if (active) setAccount(null); })
      .finally(() => { if (active) setChecking(false); });
    return () => { active = false; };
  }, [hasSessionHint]);

  if (checking) return <main className="auth-screen"><section className="auth-card auth-checking" aria-live="polite"><span className="auth-mark">⌁</span><p>Checking your secure session…</p></section></main>;
  if (!account) return <main className="auth-screen"><AuthPanel authError={authError} /></main>;
  return <ChatApp currentUser={account} />;
}
