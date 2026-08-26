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

export function mediaBucket() {
  const bucket = (env as unknown as { MEDIA?: R2Bucket }).MEDIA;
  if (!bucket) throw new Error("R2 binding MEDIA is unavailable");
  return bucket;
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
      identity_public_key TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)"),
    db.prepare(`CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      identity_public_key TEXT NOT NULL,
      identity_signature TEXT NOT NULL,
      key_package TEXT NOT NULL,
      key_package_signature TEXT NOT NULL,
      key_package_version TEXT NOT NULL DEFAULT '1',
      active TEXT NOT NULL DEFAULT '1',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS conversations (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'direct',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS device_key_packages (
      device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      version TEXT NOT NULL,
      key_package TEXT NOT NULL,
      key_package_signature TEXT NOT NULL,
      consumed_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (device_id, version)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS device_link_sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      code_hash TEXT NOT NULL,
      requester_name TEXT NOT NULL,
      requester_public_key TEXT NOT NULL,
      approver_public_key TEXT,
      encrypted_transfer TEXT,
      transfer_iv TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS encrypted_backups (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      source_device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      salt TEXT NOT NULL,
      version TEXT NOT NULL DEFAULT '1',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
      protocol TEXT NOT NULL DEFAULT 'legacy-aes-gcm',
      epoch TEXT,
      sender_device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS attachments (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      plaintext_size TEXT NOT NULL,
      ciphertext_size TEXT NOT NULL,
      thumbnail_ciphertext_size TEXT,
      object_key TEXT NOT NULL,
      thumbnail_object_key TEXT,
      retention TEXT NOT NULL DEFAULT '7d',
      status TEXT NOT NULL DEFAULT 'pending',
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      deleted_at TEXT
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS rate_limit_buckets (
      actor_key TEXT NOT NULL,
      scope TEXT NOT NULL,
      window_start INTEGER NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 0,
      cost INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL,
      PRIMARY KEY (actor_key, scope, window_start)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      metadata TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS abuse_restrictions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      scope TEXT NOT NULL,
      reason TEXT NOT NULL,
      created_by TEXT NOT NULL,
      expires_at TEXT,
      revoked_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS mls_welcomes (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      recipient_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      recipient_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      recipient_key_package_version TEXT NOT NULL,
      sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      welcome TEXT NOT NULL,
      ratchet_tree TEXT NOT NULL,
      claimed_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS mls_events (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      payload TEXT NOT NULL,
      epoch TEXT NOT NULL,
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
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_attachments_object_key ON attachments(object_key)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_attachments_conversation_status ON attachments(conversation_id, status)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_attachments_expiry_status ON attachments(expires_at, status)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_expiry ON rate_limit_buckets(expires_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_security_events_category_created ON security_events(category, created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_security_events_actor_created ON security_events(actor_id, created_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_abuse_restrictions_user_active ON abuse_restrictions(user_id, revoked_at, expires_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_devices_user_active ON devices(user_id, active)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_device_key_packages_available ON device_key_packages(device_id, consumed_at)"),
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_device_link_sessions_code_hash ON device_link_sessions(code_hash)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_device_link_sessions_user_status ON device_link_sessions(user_id, status)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_mls_welcomes_recipient_claimed ON mls_welcomes(recipient_device_id, claimed_at)"),
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_mls_welcomes_key_package_once ON mls_welcomes(recipient_device_id, recipient_key_package_version)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_mls_events_conversation_created ON mls_events(conversation_id, created_at)"),
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
