import { sessionIdentity } from "./auth";
import { encryptedMediaStore, whisperDatabase, type WhisperDatabase } from "./platform";

export type AuthenticatedIdentity = {
  userId: string;
  email: string;
  displayName: string;
};

export type D1Result<T> = { results?: T[] };

export function database() {
  return whisperDatabase;
}

export function mediaBucket() {
  if (!process.env.BLOB_READ_WRITE_TOKEN && !process.env.VERCEL_OIDC_TOKEN) {
    throw new Error("Vercel Blob is not configured");
  }
  return encryptedMediaStore;
}

export async function identity(request: Request): Promise<AuthenticatedIdentity | null> {
  if (!(request.headers.get("cookie") ?? "").includes("__Host-whisper_session=")) return null;
  await initializeDatabase();
  return sessionIdentity(database(), request);
}

export function json(data: unknown, init?: ResponseInit) {
  const headers = new Headers(init?.headers);
  headers.set("cache-control", "no-store");
  headers.set("content-type", "application/json; charset=utf-8");
  return Response.json(data, { ...init, headers });
}

let initialization: Promise<void> | null = null;

type LegacyColumn = readonly [name: string, statement: string];

async function ensureColumns(db: WhisperDatabase, table: string, additions: readonly LegacyColumn[]) {
  const columns = await db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>();
  const names = new Set((columns.results ?? []).map((column) => column.name));
  for (const [name, statement] of additions) {
    if (names.has(name)) continue;
    try {
      await db.prepare(statement).run();
      names.add(name);
    } catch (error) {
      // Concurrent serverless instances can initialize the same legacy database together.
      // Treat another request adding the expected column as success.
      const current = await db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>();
      if (!(current.results ?? []).some((column) => column.name === name)) throw error;
      names.add(name);
    }
  }
}

export async function initializeDatabase() {
  initialization ??= initializeDatabaseOnce();
  try {
    await initialization;
  } catch (error) {
    initialization = null;
    throw error;
  }
}

async function initializeDatabaseOnce() {
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
    db.prepare(`CREATE TABLE IF NOT EXISTS auth_credentials (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      password_iterations INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      user_agent_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS auth_oauth_accounts (
      provider TEXT NOT NULL,
      provider_account_id TEXT NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (provider, provider_account_id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS auth_oauth_states (
      state_hash TEXT PRIMARY KEY,
      code_verifier TEXT NOT NULL,
      nonce TEXT NOT NULL,
      return_to TEXT NOT NULL DEFAULT '/',
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS auth_email_challenges (
      challenge_hash TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      password_iterations INTEGER NOT NULL,
      code_hash TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT NOT NULL,
      consumed_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS auth_password_resets (
      challenge_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      password_iterations INTEGER NOT NULL,
      code_hash TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT NOT NULL,
      consumed_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS push_subscriptions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      endpoint TEXT NOT NULL,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
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
    db.prepare("CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_expires ON auth_sessions(user_id, expires_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_auth_oauth_accounts_user ON auth_oauth_accounts(user_id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_auth_email_challenges_email ON auth_email_challenges(email, expires_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_auth_password_resets_user_expires ON auth_password_resets(user_id, expires_at)"),
    db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_push_subscriptions_endpoint ON push_subscriptions(endpoint)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id)"),
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

  // Local Miniflare and early hosted databases can predate generated
  // migrations. Upgrade every original table in place without deleting
  // accounts, membership, or encrypted chat data.
  await ensureColumns(db, "users", [
    ["display_name", "ALTER TABLE users ADD COLUMN display_name TEXT"],
    ["identity_public_key", "ALTER TABLE users ADD COLUMN identity_public_key TEXT"],
    ["updated_at", "ALTER TABLE users ADD COLUMN updated_at TEXT"],
  ]);
  await ensureColumns(db, "conversation_members", [
    ["role", "ALTER TABLE conversation_members ADD COLUMN role TEXT NOT NULL DEFAULT 'member'"],
  ]);
  await ensureColumns(db, "messages", [
    ["protocol", "ALTER TABLE messages ADD COLUMN protocol TEXT NOT NULL DEFAULT 'legacy-aes-gcm'"],
    ["epoch", "ALTER TABLE messages ADD COLUMN epoch TEXT"],
    ["sender_device_id", "ALTER TABLE messages ADD COLUMN sender_device_id TEXT"],
  ]);
  await db.prepare("UPDATE users SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL").run();
  await db.prepare(
    `UPDATE conversation_members AS member
     SET role = 'owner'
     WHERE role = 'member'
       AND user_id = (
         SELECT candidate.user_id
         FROM conversation_members AS candidate
         WHERE candidate.conversation_id = member.conversation_id
         ORDER BY candidate.joined_at, candidate.user_id
         LIMIT 1
       )
       AND NOT EXISTS (
         SELECT 1 FROM conversation_members AS owner
         WHERE owner.conversation_id = member.conversation_id AND owner.role = 'owner'
       )`,
  ).run();
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
