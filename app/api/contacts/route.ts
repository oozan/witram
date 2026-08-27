import { database, type D1Result, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";
import { enforceWriteSafety, safetyError } from "../_lib/safety";

type StoredContact = { id: string; email: string; display_name: string | null; created_at: string };
type StoredInvitation = { id: string; user_id: string; email: string; display_name: string | null; created_at: string };

export async function GET(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  await initializeDatabase();
  await registerIdentity(current);

  const db = database();
  const [contacts, incoming, outgoing, blocked] = await Promise.all([
    db.prepare(
      `SELECT u.id, u.email, u.display_name, c.created_at
       FROM contacts c JOIN users u ON u.id = c.contact_id
       WHERE c.user_id = ? ORDER BY COALESCE(u.display_name, u.email) COLLATE NOCASE`,
    ).bind(current.userId).all() as Promise<D1Result<StoredContact>>,
    db.prepare(
      `SELECT ci.id, u.id AS user_id, u.email, u.display_name, ci.created_at
       FROM contact_invitations ci JOIN users u ON u.id = ci.sender_id
       WHERE ci.recipient_id = ? AND ci.status = 'pending' ORDER BY ci.created_at DESC`,
    ).bind(current.userId).all() as Promise<D1Result<StoredInvitation>>,
    db.prepare(
      `SELECT ci.id, u.id AS user_id, u.email, u.display_name, ci.created_at
       FROM contact_invitations ci JOIN users u ON u.id = ci.recipient_id
       WHERE ci.sender_id = ? AND ci.status = 'pending' ORDER BY ci.created_at DESC`,
    ).bind(current.userId).all() as Promise<D1Result<StoredInvitation>>,
    db.prepare(
      `SELECT u.id, u.email, u.display_name, b.created_at
       FROM blocks b JOIN users u ON u.id = b.blocked_id
       WHERE b.blocker_id = ? ORDER BY b.created_at DESC`,
    ).bind(current.userId).all() as Promise<D1Result<StoredContact>>,
  ]);

  const person = (row: StoredContact) => ({ id: row.id, email: row.email, displayName: row.display_name ?? row.email, createdAt: row.created_at });
  const invitation = (row: StoredInvitation) => ({ id: row.id, person: { id: row.user_id, email: row.email, displayName: row.display_name ?? row.email }, createdAt: row.created_at });
  return json({
    contacts: (contacts.results ?? []).map(person),
    incoming: (incoming.results ?? []).map(invitation),
    outgoing: (outgoing.results ?? []).map(invitation),
    blocked: (blocked.results ?? []).map(person),
  });
}

export async function POST(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 2_000) return json({ error: "Request body is too large" }, { status: 413 });

  let payload: { email?: unknown };
  try {
    payload = await request.json() as typeof payload;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return json({ error: "Enter a valid email address" }, { status: 400 });
  if (email === current.email) return json({ error: "You cannot invite your own account" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceWriteSafety({ userId: current.userId, scope: "contact-invites", restriction: "contacts", endpoint: "/api/contacts", limit: 8, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  const db = database();
  const recipient = await db.prepare("SELECT id, email, display_name FROM users WHERE email = ? LIMIT 1").bind(email).first<{ id: string; email: string; display_name: string | null }>();
  if (!recipient) return json({ error: "That person must sign in to Whisper once before you can invite them" }, { status: 404 });
  if (await db.prepare("SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?) LIMIT 1").bind(current.userId, recipient.id, recipient.id, current.userId).first()) {
    return json({ error: "This contact invitation is unavailable" }, { status: 403 });
  }
  if (await db.prepare("SELECT 1 FROM contacts WHERE user_id = ? AND contact_id = ? LIMIT 1").bind(current.userId, recipient.id).first()) {
    return json({ error: "This person is already in your contacts" }, { status: 409 });
  }
  if (await db.prepare(
    `SELECT 1 FROM contact_invitations WHERE status = 'pending'
     AND ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)) LIMIT 1`,
  ).bind(current.userId, recipient.id, recipient.id, current.userId).first()) {
    return json({ error: "A contact invitation is already pending" }, { status: 409 });
  }

  const id = crypto.randomUUID();
  await db.prepare("INSERT INTO contact_invitations (id, sender_id, recipient_id) VALUES (?, ?, ?)").bind(id, current.userId, recipient.id).run();
  return json({ invitation: { id, person: { id: recipient.id, email: recipient.email, displayName: recipient.display_name ?? recipient.email } } }, { status: 201 });
}

export async function PATCH(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 2_000) return json({ error: "Request body is too large" }, { status: 413 });

  let payload: { invitationId?: unknown; action?: unknown };
  try {
    payload = await request.json() as typeof payload;
  } catch {
    return json({ error: "A JSON request body is required" }, { status: 400 });
  }
  const invitationId = typeof payload.invitationId === "string" ? payload.invitationId : "";
  const action = payload.action === "accept" || payload.action === "decline" ? payload.action : null;
  if (!/^[a-f0-9-]{36}$/i.test(invitationId) || !action) return json({ error: "A valid invitation and action are required" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceWriteSafety({ userId: current.userId, scope: "contact-responses", restriction: "contacts", endpoint: "/api/contacts", limit: 40, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  const db = database();
  const invitation = await db.prepare(
    "SELECT sender_id, recipient_id FROM contact_invitations WHERE id = ? AND recipient_id = ? AND status = 'pending' LIMIT 1",
  ).bind(invitationId, current.userId).first<{ sender_id: string; recipient_id: string }>();
  if (!invitation) return json({ error: "Invitation was not found or has already been handled" }, { status: 404 });
  const respondedAt = new Date().toISOString();
  if (action === "decline") {
    await db.prepare("UPDATE contact_invitations SET status = 'declined', responded_at = ? WHERE id = ?").bind(respondedAt, invitationId).run();
    return json({ status: "declined" });
  }

  await db.batch([
    db.prepare("UPDATE contact_invitations SET status = 'accepted', responded_at = ? WHERE id = ?").bind(respondedAt, invitationId),
    db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)").bind(invitation.sender_id, invitation.recipient_id),
    db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)").bind(invitation.recipient_id, invitation.sender_id),
  ]);
  return json({ status: "accepted" });
}
