import { conversationMember, expirationFor, isMediaKind, isRetention, purgeExpiredAttachments, validateMediaSizes, validAttachmentId } from "../_lib/media";
import { database, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";
import { enforceWriteSafety, safetyError } from "../_lib/safety";

export async function POST(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 8_000) return json({ error: "Request body is too large" }, { status: 413 });

  let payload: { conversationId?: string; kind?: unknown; plaintextSize?: unknown; ciphertextSize?: unknown; thumbnailCiphertextSize?: unknown; retention?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }

  const conversationId = payload.conversationId?.trim();
  const thumbnailSize = payload.thumbnailCiphertextSize === null ? null : Number(payload.thumbnailCiphertextSize);
  if (!conversationId || !/^[a-z0-9-]{1,80}$/i.test(conversationId)) return json({ error: "A valid conversationId is required" }, { status: 400 });
  if (!isMediaKind(payload.kind) || !isRetention(payload.retention)) return json({ error: "A valid media kind and retention period are required" }, { status: 400 });
  if (!validateMediaSizes(payload.kind, Number(payload.plaintextSize), Number(payload.ciphertextSize), thumbnailSize)) return json({ error: "The encrypted media size is invalid or exceeds its limit" }, { status: 400 });

  await initializeDatabase();
  await registerIdentity(current);
  try {
    await enforceWriteSafety({ userId: current.userId, scope: "media-hour", restriction: "media", endpoint: "/api/attachments", limit: 30, windowSeconds: 3_600, cost: Math.ceil(Number(payload.plaintextSize) / 1_048_576), costLimit: 300 });
    await enforceWriteSafety({ userId: current.userId, scope: "media-day", restriction: "media", endpoint: "/api/attachments", limit: 150, windowSeconds: 86_400, cost: Math.ceil(Number(payload.plaintextSize) / 1_048_576), costLimit: 1_500 });
  } catch (error) { return safetyError(error); }
  await purgeExpiredAttachments();
  if (!await conversationMember(conversationId, current.userId)) return json({ error: "You are not a member of this conversation" }, { status: 403 });

  const id = crypto.randomUUID();
  const objectKey = `conversations/${conversationId}/${id}/original.bin`;
  const thumbnailObjectKey = thumbnailSize === null ? null : `conversations/${conversationId}/${id}/thumbnail.bin`;
  const expiresAt = expirationFor(payload.retention);
  await database().prepare(
    `INSERT INTO attachments
      (id, conversation_id, owner_id, kind, plaintext_size, ciphertext_size, thumbnail_ciphertext_size, object_key, thumbnail_object_key, retention, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(id, conversationId, current.userId, payload.kind, String(payload.plaintextSize), String(payload.ciphertextSize), thumbnailSize === null ? null : String(thumbnailSize), objectKey, thumbnailObjectKey, payload.retention, expiresAt).run();

  return json({ attachment: { id, expiresAt } }, { status: 201 });
}

export async function PATCH(request: Request) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  let payload: { id?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  if (!validAttachmentId(payload.id)) return json({ error: "A valid attachment id is required" }, { status: 400 });

  await initializeDatabase();
  const db = database();
  const row = await db.prepare("SELECT * FROM attachments WHERE id = ? AND owner_id = ? LIMIT 1").bind(payload.id, current.userId).first() as Record<string, unknown> | null;
  if (!row) return json({ error: "Attachment not found" }, { status: 404 });
  if (row.status === "deleted") return json({ error: "Attachment has expired or was deleted" }, { status: 410 });

  const { mediaBucket } = await import("../_lib/social");
  const bucket = mediaBucket();
  const original = await bucket.head(String(row.object_key));
  const thumbnail = row.thumbnail_object_key ? await bucket.head(String(row.thumbnail_object_key)) : null;
  if (!original || original.size !== Number(row.ciphertext_size) || (row.thumbnail_object_key && (!thumbnail || thumbnail.size !== Number(row.thumbnail_ciphertext_size)))) {
    return json({ error: "Encrypted upload is incomplete" }, { status: 409 });
  }
  const now = new Date().toISOString();
  await db.prepare("UPDATE attachments SET status = 'ready', updated_at = ? WHERE id = ?").bind(now, payload.id).run();
  return json({ attachment: { id: payload.id, status: "ready", expiresAt: row.expires_at } });
}
