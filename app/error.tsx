"use client";

import { useEffect } from "react";

export default function ErrorScreen({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error("Whisper application error", error);
  }, [error]);

  return (
    <main className="error-screen">
      <section className="error-card" role="alert">
        <span aria-hidden="true">⌁</span>
        <h2>Whisper needs a quick reconnect</h2>
        <p>Your encrypted drafts and device keys remain on this device. Retry to restore the conversation interface.</p>
        <button onClick={() => reset()}>Retry Whisper</button>
      </section>
    </main>
  );
}
