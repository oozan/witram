import { requireSameOrigin } from "../_lib/auth";
import { database, type D1Result, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";
import { enforceWriteSafety, recordSecurityEvent, safetyError } from "../_lib/safety";

type StoredConversation = {
  id: string;
  title: string;
  kind: "direct" | "group" | "saved";
  created_at: string;
  last_activity: string;
  message_count: number;
  member_ids: string | null;
  current_role: "owner" | "member";
};

export async function GET(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });

  await initializeDatabase();
  await registerIdentity(current);
  const result = await database().prepare(
    `SELECT c.id, c.title, c.kind, c.created_at, cm.role AS current_role,
            COALESCE(MAX(m.created_at), c.created_at) AS last_activity,
            COUNT(m.id) AS message_count,
            (SELECT GROUP_CONCAT(cm2.user_id) FROM conversation_members cm2
             WHERE cm2.conversation_id = c.id AND cm2.user_id != ?) AS member_ids
     FROM conversations c
     JOIN conversation_members cm ON cm.conversation_id = c.id
     LEFT JOIN messages m ON m.conversation_id = c.id
     WHERE cm.user_id = ?
     GROUP BY c.id, c.title, c.kind, c.created_at, cm.role
     ORDER BY last_activity DESC, c.id ASC
     LIMIT 100`,
  ).bind(current.userId, current.userId).all() as D1Result<StoredConversation>;

  return json({
    conversations: (result.results ?? []).map((conversation) => ({
      id: conversation.id,
      title: conversation.title,
      kind: conversation.kind,
      createdAt: conversation.created_at,
      lastActivity: conversation.last_activity,
      messageCount: Number(conversation.message_count),
      memberIds: conversation.member_ids?.split(",").filter(Boolean) ?? [],
      role: conversation.current_role,
    })),
  });
}

export async function POST(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Conversation request rejected" }, { status: 403 }); }
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });

  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > 2_000) return json({ error: "Request body is too large" }, { status: 413 });

  let payload: { title?: unknown; kind?: unknown; memberIds?: unknown };
  try {
    payload = await request.json() as typeof payload;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }

  const title = typeof payload.title === "string" ? payload.title.trim().replace(/\s+/g, " ") : "";
  const kind = payload.kind === "group" || payload.kind === "saved" ? payload.kind : "direct";
  const memberIds = Array.isArray(payload.memberIds)
    ? Array.from(new Set(payload.memberIds.filter((value): value is string => typeof value === "string" && value.trim().length > 0).map((value) => value.trim()))).slice(0, 99)
    : [];
  if (title.length < 1 || title.length > 80) {
    return json({ error: "Conversation title must be between 1 and 80 characters" }, { status: 400 });
  }

  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceWriteSafety({ userId: current.userId, scope: "conversation-create", restriction: "contacts", endpoint: "/api/conversations", limit: 20, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  const db = database();
  if (kind === "saved" && memberIds.length) return json({ error: "Saved conversations cannot contain other members" }, { status: 400 });
  if (kind === "direct" && memberIds.length !== 1) return json({ error: "Choose one accepted contact for a direct conversation" }, { status: 400 });
  if (kind === "group" && memberIds.length < 1) return json({ error: "Choose at least one accepted contact for a group" }, { status: 400 });
  for (const memberId of memberIds) {
    const accepted = await db.prepare(
      `SELECT 1 FROM contacts c
       WHERE c.user_id = ? AND c.contact_id = ?
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker_id = ? AND b.blocked_id = ?) OR (b.blocker_id = ? AND b.blocked_id = ?))
       LIMIT 1`,
    ).bind(current.userId, memberId, current.userId, memberId, memberId, current.userId).first();
    if (!accepted) return json({ error: "Every conversation member must be an accepted, unblocked contact" }, { status: 403 });
  }
  const id = `chat-${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  await db.batch([
    db.prepare("INSERT INTO conversations (id, title, kind, created_at) VALUES (?, ?, ?, ?)").bind(id, title, kind, createdAt),
    db.prepare("INSERT INTO conversation_members (conversation_id, user_id, role) VALUES (?, ?, 'owner')").bind(id, current.userId),
    ...memberIds.map((memberId) => db.prepare("INSERT INTO conversation_members (conversation_id, user_id, role) VALUES (?, ?, 'member')").bind(id, memberId)),
  ]);

  return json({ conversation: { id, title, kind, createdAt, lastActivity: createdAt, messageCount: 0, memberIds, role: "owner" } }, { status: 201 });
}

export async function PATCH(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Conversation request rejected" }, { status: 403 }); }
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 2_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: { conversationId?: unknown; action?: unknown; memberId?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const conversationId = typeof payload.conversationId === "string" ? payload.conversationId.trim() : "";
  const memberId = typeof payload.memberId === "string" ? payload.memberId.trim() : "";
  const action = payload.action;
  if (!/^[a-z0-9-]{1,80}$/i.test(conversationId) || !/^usr_[a-f0-9-]{36}$/i.test(memberId) || (action !== "add" && action !== "remove")) return json({ error: "A valid group membership change is required" }, { status: 400 });
  if (memberId === current.userId) return json({ error: "The group owner cannot remove their own membership" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceWriteSafety({ userId: current.userId, scope: "group-membership", restriction: "contacts", endpoint: "/api/conversations", limit: 40, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  const db = database();
  const group = await db.prepare(
    `SELECT c.id FROM conversations c JOIN conversation_members cm ON cm.conversation_id = c.id
     WHERE c.id = ? AND c.kind = 'group' AND cm.user_id = ? AND cm.role = 'owner' LIMIT 1`,
  ).bind(conversationId, current.userId).first();
  if (!group) return json({ error: "Only the group owner can change membership" }, { status: 403 });

  if (action === "add") {
    const count = await db.prepare("SELECT COUNT(*) AS count FROM conversation_members WHERE conversation_id = ?").bind(conversationId).first<{ count: number }>();
    if (Number(count?.count ?? 0) >= 100) return json({ error: "Groups are limited to 100 members" }, { status: 409 });
    const accepted = await db.prepare(
      `SELECT 1 FROM contacts c WHERE c.user_id = ? AND c.contact_id = ?
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker_id = ? AND b.blocked_id = ?) OR (b.blocker_id = ? AND b.blocked_id = ?)) LIMIT 1`,
    ).bind(current.userId, memberId, current.userId, memberId, memberId, current.userId).first();
    if (!accepted) return json({ error: "New members must be accepted, unblocked contacts" }, { status: 403 });
    try { await db.prepare("INSERT INTO conversation_members (conversation_id, user_id, role) VALUES (?, ?, 'member')").bind(conversationId, memberId).run(); }
    catch { return json({ error: "This contact is already a group member" }, { status: 409 }); }
  } else {
    const removed = await db.prepare("DELETE FROM conversation_members WHERE conversation_id = ? AND user_id = ? AND role = 'member'").bind(conversationId, memberId).run();
    if (!removed.meta.changes) return json({ error: "Group member was not found" }, { status: 404 });
    await db.prepare("DELETE FROM mls_welcomes WHERE conversation_id = ? AND recipient_user_id = ?").bind(conversationId, memberId).run();
  }
  const members = await db.prepare("SELECT user_id FROM conversation_members WHERE conversation_id = ? AND user_id != ? ORDER BY joined_at, user_id").bind(conversationId, current.userId).all<{ user_id: string }>();
  await recordSecurityEvent({ actorId: current.userId, category: `group_member_${action}ed`, severity: "info", endpoint: "/api/conversations", metadata: { conversationId, memberId } });
  return json({ memberIds: (members.results ?? []).map((member) => member.user_id) });
}
