import { sql } from "drizzle-orm";
import { index, primaryKey, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  email: text("email"),
  displayName: text("display_name"),
  publicKey: text("public_key"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
}, (table) => [uniqueIndex("idx_users_email").on(table.email)]);

export const conversations = sqliteTable("conversations", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  kind: text("kind", { enum: ["direct", "group", "saved"] }).notNull().default("direct"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
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
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [index("idx_messages_conversation_created_at").on(table.conversationId, table.createdAt)],
);
