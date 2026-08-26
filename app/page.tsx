import { ChatApp } from "./chat-app";
import { chatGPTSignInPath, getChatGPTUser } from "./chatgpt-auth";

export const dynamic = "force-dynamic";

export default async function Home() {
  const user = await getChatGPTUser();
  if (!user) {
    return (
      <main className="auth-screen">
        <section className="auth-card">
          <span className="auth-mark">⌁</span>
          <p className="auth-eyebrow">Private by design</p>
          <h1>Welcome to Whisper</h1>
          <p>Sign in securely to create your account, connect with people you trust, and access your encrypted conversations.</p>
          <a href={chatGPTSignInPath("/")}>Sign in with ChatGPT</a>
          <small>Your ChatGPT identity is used for authentication. Whisper never asks for or stores your password.</small>
          <nav className="auth-legal-links" aria-label="Legal"><a href="/security">Security</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a></nav>
        </section>
      </main>
    );
  }
  return <ChatApp currentUser={{ id: user.userId, email: user.email, displayName: user.displayName }} />;
}
