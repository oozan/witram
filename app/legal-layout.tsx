import Link from "next/link";
import styles from "./legal.module.css";

export function LegalLayout({ title, summary, children }: { title: string; summary: string; children: React.ReactNode }) {
  return <main className={styles.page}>
    <article className={styles.document}>
      <header>
        <Link className={styles.brand} href="/"><span>⌁</span> Whisper</Link>
        <p>Effective August 26, 2026</p>
        <h1>{title}</h1>
        <strong>{summary}</strong>
      </header>
      <div className={styles.content}>{children}</div>
      <footer><Link href="/">Return to Whisper</Link><span>·</span><Link href="/security">Security</Link><span>·</span><Link href="/privacy">Privacy</Link><span>·</span><Link href="/terms">Terms</Link></footer>
    </article>
  </main>;
}
