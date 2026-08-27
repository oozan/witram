import { database, identity, initializeDatabase, json, registerIdentity } from "../../_lib/social";
import { enforceRateLimit, safetyError } from "../../_lib/safety";

type StoredLink = {
  id: string;
  code_hash: string;
  requester_name: string;
  requester_public_key: string;
  approver_public_key: string | null;
  encrypted_transfer: string | null;
  transfer_iv: string | null;
  status: "pending" | "confirming" | "ready" | "claimed" | "cancelled";
  expires_at: string;
  created_at: string;
};

function validBase64(value: unknown, maximum: number) {
  return typeof value === "string" && value.length >= 4 && value.length <= maximum && /^[A-Za-z0-9+/=]+$/.test(value);
}

function decodedLength(value: unknown) {
  if (!validBase64(value, 256)) return 0;
  try { return Uint8Array.from(atob(value as string), (character) => character.charCodeAt(0)).length; } catch { return 0; }
}

function present(link: StoredLink) {
  return {
    id: link.id,
    requesterName: link.requester_name,
    requesterPublicKey: link.requester_public_key,
    approverPublicKey: link.approver_public_key,
    encryptedTransfer: link.encrypted_transfer,
    transferIv: link.transfer_iv,
    status: link.status,
    expiresAt: link.expires_at,
    createdAt: link.created_at,
  };
}

export async function POST(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 4_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: Record<string, unknown>;
  try { payload = await request.json() as Record<string, unknown>; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const requesterName = typeof payload.requesterName === "string" ? payload.requesterName.trim().replace(/\s+/g, " ").slice(0, 60) : "";
  if (requesterName.length < 2 || decodedLength(payload.requesterPublicKey) !== 32 || decodedLength(payload.codeHash) !== 32) return json({ error: "A valid device-link request is required" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceRateLimit({ actorKey: `user:${current.userId}`, actorId: current.userId, scope: "device-link-create", endpoint: "/api/devices/links", limit: 12, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  const db = database();
  const now = new Date();
  await db.prepare("UPDATE device_link_sessions SET status = 'cancelled', updated_at = ? WHERE user_id = ? AND status IN ('pending', 'confirming') AND expires_at <= ?").bind(now.toISOString(), current.userId, now.toISOString()).run();
  const id = crypto.randomUUID();
  const expiresAt = new Date(now.getTime() + 10 * 60_000).toISOString();
  try {
    await db.prepare("INSERT INTO device_link_sessions (id, user_id, code_hash, requester_name, requester_public_key, expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(id, current.userId, payload.codeHash, requesterName, payload.requesterPublicKey, expiresAt, now.toISOString()).run();
  } catch {
    return json({ error: "That link request already exists" }, { status: 409 });
  }
  return json({ link: { id, status: "pending", expiresAt } }, { status: 201 });
}

export async function GET(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  await initializeDatabase();
  await registerIdentity(current);
  const url = new URL(request.url);
  const linkId = url.searchParams.get("linkId")?.trim();
  const codeHash = url.searchParams.get("codeHash")?.trim();
  if (!linkId && !codeHash) return json({ error: "A link identifier or code hash is required" }, { status: 400 });
  const link = await database().prepare(
    `SELECT id, code_hash, requester_name, requester_public_key, approver_public_key, encrypted_transfer, transfer_iv, status, expires_at, created_at
     FROM device_link_sessions WHERE user_id = ? AND ${linkId ? "id" : "code_hash"} = ? LIMIT 1`,
  ).bind(current.userId, linkId || codeHash).first<StoredLink>();
  if (!link || link.status === "cancelled" || new Date(link.expires_at).getTime() <= Date.now()) return json({ error: "Device-link request was not found or has expired" }, { status: 404 });
  return json({ link: present(link) });
}

export async function PATCH(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 1_500_000) return json({ error: "Request body is too large" }, { status: 413 });
  let payload: Record<string, unknown>;
  try { payload = await request.json() as Record<string, unknown>; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  const linkId = typeof payload.linkId === "string" ? payload.linkId : "";
  const action = payload.action;
  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceRateLimit({ actorKey: `user:${current.userId}`, actorId: current.userId, scope: "device-link-actions", endpoint: "/api/devices/links", limit: 60, windowSeconds: 3_600, cost: Math.ceil(Number(request.headers.get("content-length") ?? 0) / 65_536), costLimit: 100 }); } catch (error) { return safetyError(error); }
  const db = database();
  const now = new Date().toISOString();
  const link = await db.prepare("SELECT id, code_hash, requester_name, requester_public_key, approver_public_key, encrypted_transfer, transfer_iv, status, expires_at, created_at FROM device_link_sessions WHERE id = ? AND user_id = ? LIMIT 1").bind(linkId, current.userId).first<StoredLink>();
  if (!link || new Date(link.expires_at).getTime() <= Date.now() || link.status === "cancelled") return json({ error: "Device-link request was not found or has expired" }, { status: 404 });
  if (action !== "cancel" && payload.codeHash !== link.code_hash) return json({ error: "Device-link capability proof is invalid" }, { status: 403 });

  if (action === "offer") {
    if (link.status !== "pending" || decodedLength(payload.approverPublicKey) !== 32) return json({ error: "Link request cannot accept an offer" }, { status: 409 });
    await db.prepare("UPDATE device_link_sessions SET approver_public_key = ?, status = 'confirming', updated_at = ? WHERE id = ? AND status = 'pending'").bind(payload.approverPublicKey, now, linkId).run();
  } else if (action === "transfer") {
    if (link.status !== "confirming" || !validBase64(payload.encryptedTransfer, 1_400_000) || decodedLength(payload.transferIv) !== 12) return json({ error: "A confirmed encrypted transfer is required" }, { status: 409 });
    await db.prepare("UPDATE device_link_sessions SET encrypted_transfer = ?, transfer_iv = ?, status = 'ready', updated_at = ? WHERE id = ? AND status = 'confirming'").bind(payload.encryptedTransfer, payload.transferIv, now, linkId).run();
  } else if (action === "claim") {
    if (link.status !== "ready") return json({ error: "Encrypted transfer is not ready" }, { status: 409 });
    await db.prepare("UPDATE device_link_sessions SET status = 'claimed', encrypted_transfer = NULL, transfer_iv = NULL, updated_at = ? WHERE id = ? AND status = 'ready'").bind(now, linkId).run();
  } else if (action === "cancel") {
    await db.prepare("UPDATE device_link_sessions SET status = 'cancelled', encrypted_transfer = NULL, transfer_iv = NULL, updated_at = ? WHERE id = ? AND user_id = ?").bind(now, linkId, current.userId).run();
  } else {
    return json({ error: "Unknown device-link action" }, { status: 400 });
  }
  const updated = await db.prepare("SELECT id, code_hash, requester_name, requester_public_key, approver_public_key, encrypted_transfer, transfer_iv, status, expires_at, created_at FROM device_link_sessions WHERE id = ? LIMIT 1").bind(linkId).first<StoredLink>();
  return json({ link: updated ? present(updated) : null });
}
