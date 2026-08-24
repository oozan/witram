import { env } from "cloudflare:workers";

export type AuthenticatedIdentity = {
  userId: string;
  email: string;
  displayName: string;
};

export type D1Result<T> = { results?: T[] };

export function database() {
  if (!env.DB) throw new Error("D1 binding DB is unavailable");
  return env.DB;
}

export function identity(request: Request): AuthenticatedIdentity | null {
  const userId = request.headers.get("oai-authenticated-user-id")?.trim();
  const email = request.headers.get("oai-authenticated-user-email")?.trim().toLowerCase();
  if (!userId || !email) return null;

  const encodedName = request.headers.get("oai-authenticated-user-full-name");
  const encoding = request.headers.get("oai-authenticated-user-full-name-encoding");
  let displayName = email.split("@")[0];
  if (encodedName && encoding === "percent-encoded-utf-8") {
    try {
      displayName = decodeURIComponent(encodedName).trim() || displayName;
    } catch {
      // The authenticated email remains a safe display fallback.
    }
  }
  return { userId, email, displayName };
}

export function json(data: unknown, init?: ResponseInit) {
  const headers = new Headers(init?.headers);
  headers.set("cache-control", "no-store");
  headers.set("content-type", "application/json; charset=utf-8");
  return Response.json(data, { ...init, headers });
}

export async function initializeDatabase() {
  const db = database();
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT,
      display_name TEXT,
      public_key TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS conversations (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'direct',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS conversation_members (
      conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      wrapped_key TEXT,
      role TEXT NOT NULL DEFAULT 'member',
      joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (conversation_id, user_id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      sender_id TEXT NOT NULL REFERENCES users(id),
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'AES-GCM-256',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS contact_invitations (
      id TEXT PRIMARY KEY,
      sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      responded_at TEXT
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS contacts (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      contact_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, contact_id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS blocks (
      blocker_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (blocker_id, blocked_id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reported_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      conversation_id TEXT REFERENCES conversations(id) ON DELETE SET NULL,
      category TEXT NOT NULL,
      details TEXT,
      status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_conversation_members_user_id ON conversation_members(user_id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_messages_conversation_created_at ON messages(conversation_id, created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_contact_invitations_recipient_status ON contact_invitations(recipient_id, status)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_contact_invitations_sender_status ON contact_invitations(sender_id, status)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_contacts_contact_id ON contacts(contact_id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_blocks_blocked_id ON blocks(blocked_id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_reports_reported_user_status ON reports(reported_user_id, status)"),
  ]);
}

export async function registerIdentity(current: AuthenticatedIdentity) {
  const db = database();
  await db.prepare(
    `INSERT INTO users (id, email, display_name, updated_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET email = excluded.email,
       display_name = COALESCE(users.display_name, excluded.display_name), updated_at = excluded.updated_at`,
  ).bind(current.userId, current.email, current.displayName, new Date().toISOString()).run();
}

export async function hasBlockedRelationship(firstUserId: string, secondUserId: string) {
  return Boolean(await database().prepare(
    `SELECT 1 FROM blocks
     WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)
     LIMIT 1`,
  ).bind(firstUserId, secondUserId, secondUserId, firstUserId).first());
}

export function cleanDisplayName(value: unknown) {
  return typeof value === "string" ? value.trim().replace(/\s+/g, " ").slice(0, 60) : "";
}
