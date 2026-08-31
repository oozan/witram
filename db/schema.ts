import { sql } from "drizzle-orm";
import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  email: text("email"),
  displayName: text("display_name"),
  publicKey: text("public_key"),
  identityPublicKey: text("identity_public_key"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
}, (table) => [uniqueIndex("idx_users_email").on(table.email)]);

export const authCredentials = sqliteTable("auth_credentials", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  passwordHash: text("password_hash").notNull(),
  passwordSalt: text("password_salt").notNull(),
  passwordIterations: integer("password_iterations").notNull(),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const authSessions = sqliteTable("auth_sessions", {
  tokenHash: text("token_hash").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  expiresAt: text("expires_at").notNull(),
  userAgentHash: text("user_agent_hash").notNull(),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  lastSeenAt: text("last_seen_at").notNull().default(sql`CURRENT_TIMESTAMP`),
}, (table) => [index("idx_auth_sessions_user_expires").on(table.userId, table.expiresAt)]);

export const authOauthAccounts = sqliteTable("auth_oauth_accounts", {
  provider: text("provider").notNull(),
  providerAccountId: text("provider_account_id").notNull(),
  userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
}, (table) => [
  primaryKey({ columns: [table.provider, table.providerAccountId] }),
  index("idx_auth_oauth_accounts_user").on(table.userId),
]);

export const authOauthStates = sqliteTable("auth_oauth_states", {
  stateHash: text("state_hash").primaryKey(),
  codeVerifier: text("code_verifier").notNull(),
  nonce: text("nonce").notNull(),
  returnTo: text("return_to").notNull().default("/"),
  expiresAt: text("expires_at").notNull(),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const authEmailChallenges = sqliteTable("auth_email_challenges", {
  challengeHash: text("challenge_hash").primaryKey(),
  email: text("email").notNull(),
  displayName: text("display_name").notNull(),
  passwordHash: text("password_hash").notNull(),
  passwordSalt: text("password_salt").notNull(),
  passwordIterations: integer("password_iterations").notNull(),
  codeHash: text("code_hash").notNull(),
  attempts: integer("attempts").notNull().default(0),
  expiresAt: text("expires_at").notNull(),
  consumedAt: text("consumed_at"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
}, (table) => [index("idx_auth_email_challenges_email").on(table.email, table.expiresAt)]);

export const authPasswordResets = sqliteTable("auth_password_resets", {
  challengeHash: text("challenge_hash").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  passwordHash: text("password_hash").notNull(),
  passwordSalt: text("password_salt").notNull(),
  passwordIterations: integer("password_iterations").notNull(),
  codeHash: text("code_hash").notNull(),
  attempts: integer("attempts").notNull().default(0),
  expiresAt: text("expires_at").notNull(),
  consumedAt: text("consumed_at"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
}, (table) => [index("idx_auth_password_resets_user_expires").on(table.userId, table.expiresAt)]);

export const pushSubscriptions = sqliteTable("push_subscriptions", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  endpoint: text("endpoint").notNull(),
  p256dh: text("p256dh").notNull(),
  auth: text("auth").notNull(),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
}, (table) => [
  uniqueIndex("idx_push_subscriptions_endpoint").on(table.endpoint),
  index("idx_push_subscriptions_user").on(table.userId),
]);

export const conversations = sqliteTable("conversations", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  kind: text("kind", { enum: ["direct", "group", "saved"] }).notNull().default("direct"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const devices = sqliteTable(
  "devices",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    identityPublicKey: text("identity_public_key").notNull(),
    identitySignature: text("identity_signature").notNull(),
    keyPackage: text("key_package").notNull(),
    keyPackageSignature: text("key_package_signature").notNull(),
    keyPackageVersion: text("key_package_version").notNull().default("1"),
    active: text("active").notNull().default("1"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("idx_devices_user_active").on(table.userId, table.active)],
);

export const deviceKeyPackages = sqliteTable(
  "device_key_packages",
  {
    deviceId: text("device_id").notNull().references(() => devices.id, { onDelete: "cascade" }),
    version: text("version").notNull(),
    keyPackage: text("key_package").notNull(),
    keyPackageSignature: text("key_package_signature").notNull(),
    consumedAt: text("consumed_at"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    primaryKey({ columns: [table.deviceId, table.version] }),
    index("idx_device_key_packages_available").on(table.deviceId, table.consumedAt),
  ],
);

export const deviceLinkSessions = sqliteTable(
  "device_link_sessions",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    codeHash: text("code_hash").notNull(),
    requesterName: text("requester_name").notNull(),
    requesterPublicKey: text("requester_public_key").notNull(),
    approverPublicKey: text("approver_public_key"),
    encryptedTransfer: text("encrypted_transfer"),
    transferIv: text("transfer_iv"),
    status: text("status", { enum: ["pending", "confirming", "ready", "claimed", "cancelled"] }).notNull().default("pending"),
    expiresAt: text("expires_at").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    uniqueIndex("idx_device_link_sessions_code_hash").on(table.codeHash),
    index("idx_device_link_sessions_user_status").on(table.userId, table.status),
  ],
);

export const encryptedBackups = sqliteTable("encrypted_backups", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  sourceDeviceId: text("source_device_id").references(() => devices.id, { onDelete: "set null" }),
  ciphertext: text("ciphertext").notNull(),
  iv: text("iv").notNull(),
  salt: text("salt").notNull(),
  version: text("version").notNull().default("1"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
});

export const conversationMembers = sqliteTable(
  "conversation_members",
  {
    conversationId: text("conversation_id").notNull().references(() => conversations.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    wrappedKey: text("wrapped_key"),
    role: text("role", { enum: ["owner", "member"] }).notNull().default("member"),
    joinedAt: text("joined_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    primaryKey({ columns: [table.conversationId, table.userId] }),
    index("idx_conversation_members_user_id").on(table.userId),
  ],
);

export const contactInvitations = sqliteTable(
  "contact_invitations",
  {
    id: text("id").primaryKey(),
    senderId: text("sender_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    recipientId: text("recipient_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    status: text("status", { enum: ["pending", "accepted", "declined", "cancelled"] }).notNull().default("pending"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    respondedAt: text("responded_at"),
  },
  (table) => [
    index("idx_contact_invitations_recipient_status").on(table.recipientId, table.status),
    index("idx_contact_invitations_sender_status").on(table.senderId, table.status),
  ],
);

export const contacts = sqliteTable(
  "contacts",
  {
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    contactId: text("contact_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    primaryKey({ columns: [table.userId, table.contactId] }),
    index("idx_contacts_contact_id").on(table.contactId),
  ],
);

export const blocks = sqliteTable(
  "blocks",
  {
    blockerId: text("blocker_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    blockedId: text("blocked_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    primaryKey({ columns: [table.blockerId, table.blockedId] }),
    index("idx_blocks_blocked_id").on(table.blockedId),
  ],
);

export const reports = sqliteTable(
  "reports",
  {
    id: text("id").primaryKey(),
    reporterId: text("reporter_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    reportedUserId: text("reported_user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    conversationId: text("conversation_id").references(() => conversations.id, { onDelete: "set null" }),
    category: text("category", { enum: ["spam", "harassment", "impersonation", "illegal", "other"] }).notNull(),
    details: text("details"),
    status: text("status", { enum: ["open", "reviewing", "resolved"] }).notNull().default("open"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("idx_reports_reported_user_status").on(table.reportedUserId, table.status)],
);

export const messages = sqliteTable(
  "messages",
  {
    id: text("id").primaryKey(),
    conversationId: text("conversation_id").notNull().references(() => conversations.id, { onDelete: "cascade" }),
    senderId: text("sender_id").notNull().references(() => users.id),
    ciphertext: text("ciphertext").notNull(),
    iv: text("iv").notNull(),
    algorithm: text("algorithm").notNull().default("AES-GCM-256"),
    protocol: text("protocol").notNull().default("legacy-aes-gcm"),
    epoch: text("epoch"),
    senderDeviceId: text("sender_device_id").references(() => devices.id, { onDelete: "set null" }),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("idx_messages_conversation_created_at").on(table.conversationId, table.createdAt)],
);

export const attachments = sqliteTable(
  "attachments",
  {
    id: text("id").primaryKey(),
    conversationId: text("conversation_id").notNull().references(() => conversations.id, { onDelete: "cascade" }),
    ownerId: text("owner_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    kind: text("kind", { enum: ["image", "video", "gif", "audio", "file"] }).notNull(),
    plaintextSize: text("plaintext_size").notNull(),
    ciphertextSize: text("ciphertext_size").notNull(),
    thumbnailCiphertextSize: text("thumbnail_ciphertext_size"),
    objectKey: text("object_key").notNull(),
    thumbnailObjectKey: text("thumbnail_object_key"),
    retention: text("retention", { enum: ["1d", "7d", "30d", "forever"] }).notNull().default("7d"),
    status: text("status", { enum: ["pending", "ready", "deleted"] }).notNull().default("pending"),
    expiresAt: text("expires_at"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
    deletedAt: text("deleted_at"),
  },
  (table) => [
    uniqueIndex("idx_attachments_object_key").on(table.objectKey),
    index("idx_attachments_conversation_status").on(table.conversationId, table.status),
    index("idx_attachments_expiry_status").on(table.expiresAt, table.status),
  ],
);

export const rateLimitBuckets = sqliteTable(
  "rate_limit_buckets",
  {
    actorKey: text("actor_key").notNull(),
    scope: text("scope").notNull(),
    windowStart: integer("window_start").notNull(),
    requestCount: integer("request_count").notNull().default(0),
    cost: integer("cost").notNull().default(0),
    expiresAt: integer("expires_at").notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.actorKey, table.scope, table.windowStart] }),
    index("idx_rate_limit_buckets_expiry").on(table.expiresAt),
  ],
);

export const securityEvents = sqliteTable(
  "security_events",
  {
    id: text("id").primaryKey(),
    actorId: text("actor_id").references(() => users.id, { onDelete: "set null" }),
    category: text("category").notNull(),
    severity: text("severity", { enum: ["info", "warning", "critical"] }).notNull(),
    endpoint: text("endpoint").notNull(),
    metadata: text("metadata").notNull().default("{}"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_security_events_created_at").on(table.createdAt),
    index("idx_security_events_category_created").on(table.category, table.createdAt),
    index("idx_security_events_actor_created").on(table.actorId, table.createdAt),
  ],
);

export const abuseRestrictions = sqliteTable(
  "abuse_restrictions",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    scope: text("scope", { enum: ["all", "messages", "media", "contacts"] }).notNull(),
    reason: text("reason").notNull(),
    createdBy: text("created_by").notNull(),
    expiresAt: text("expires_at"),
    revokedAt: text("revoked_at"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("idx_abuse_restrictions_user_active").on(table.userId, table.revokedAt, table.expiresAt)],
);

export const mlsWelcomes = sqliteTable(
  "mls_welcomes",
  {
    id: text("id").primaryKey(),
    conversationId: text("conversation_id").notNull().references(() => conversations.id, { onDelete: "cascade" }),
    recipientUserId: text("recipient_user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    recipientDeviceId: text("recipient_device_id").notNull().references(() => devices.id, { onDelete: "cascade" }),
    recipientKeyPackageVersion: text("recipient_key_package_version").notNull(),
    senderDeviceId: text("sender_device_id").notNull().references(() => devices.id, { onDelete: "cascade" }),
    welcome: text("welcome").notNull(),
    ratchetTree: text("ratchet_tree").notNull(),
    claimedAt: text("claimed_at"),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_mls_welcomes_recipient_claimed").on(table.recipientDeviceId, table.claimedAt),
    uniqueIndex("idx_mls_welcomes_key_package_once").on(table.recipientDeviceId, table.recipientKeyPackageVersion),
  ],
);

export const mlsEvents = sqliteTable(
  "mls_events",
  {
    id: text("id").primaryKey(),
    conversationId: text("conversation_id").notNull().references(() => conversations.id, { onDelete: "cascade" }),
    senderDeviceId: text("sender_device_id").notNull().references(() => devices.id, { onDelete: "cascade" }),
    kind: text("kind", { enum: ["commit"] }).notNull(),
    payload: text("payload").notNull(),
    epoch: text("epoch").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("idx_mls_events_conversation_created").on(table.conversationId, table.createdAt)],
);
