import { attachmentForUser, purgeExpiredAttachments, validAttachmentId } from "../../_lib/media";
import { database, identity, initializeDatabase, json, mediaBucket } from "../../_lib/social";

type RouteContext = { params: Promise<{ id: string }> };

export async function PUT(request: Request, context: RouteContext) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  const { id } = await context.params;
  if (!validAttachmentId(id)) return json({ error: "A valid attachment id is required" }, { status: 400 });
  const part = new URL(request.url).searchParams.get("part");
  if (part !== "original" && part !== "thumbnail") return json({ error: "Upload part must be original or thumbnail" }, { status: 400 });

  await initializeDatabase();
  const row = await attachmentForUser(id, current.userId);
  if (!row || row.owner_id !== current.userId) return json({ error: "Attachment not found" }, { status: 404 });
  if (row.status !== "pending") return json({ error: "Attachment is no longer accepting uploads" }, { status: 409 });
  const objectKey = part === "original" ? row.object_key : row.thumbnail_object_key;
  const expectedSize = Number(part === "original" ? row.ciphertext_size : row.thumbnail_ciphertext_size);
  const contentLength = Number(request.headers.get("content-length"));
  if (!objectKey || !Number.isSafeInteger(contentLength) || contentLength !== expectedSize || !request.body) return json({ error: "Encrypted upload size does not match the reservation" }, { status: 400 });

  await mediaBucket().put(objectKey, request.body, {
    httpMetadata: { contentType: "application/octet-stream" },
    customMetadata: { encryption: "AES-GCM-256", part },
  });
  return json({ uploaded: true, part });
}

export async function GET(request: Request, context: RouteContext) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  const { id } = await context.params;
  if (!validAttachmentId(id)) return json({ error: "A valid attachment id is required" }, { status: 400 });
  const part = new URL(request.url).searchParams.get("part") === "thumbnail" ? "thumbnail" : "original";

  await initializeDatabase();
  await purgeExpiredAttachments();
  const row = await attachmentForUser(id, current.userId);
  if (!row) return json({ error: "Attachment not found" }, { status: 404 });
  if (row.status === "deleted") return json({ error: "Attachment has expired or was deleted" }, { status: 410 });
  if (row.status !== "ready") return json({ error: "Attachment upload is incomplete" }, { status: 409 });
  const objectKey = part === "thumbnail" ? row.thumbnail_object_key : row.object_key;
  if (!objectKey) return json({ error: "This attachment has no thumbnail" }, { status: 404 });
  const object = await mediaBucket().get(objectKey);
  if (!object) return json({ error: "Encrypted media object is unavailable" }, { status: 404 });

  return new Response(object.body, { headers: {
    "cache-control": "private, no-store, max-age=0",
    "content-disposition": "attachment",
    "content-length": String(object.size),
    "content-type": "application/octet-stream",
    "x-content-type-options": "nosniff",
    "x-whisper-encryption": "AES-GCM-256",
  } });
}

export async function DELETE(request: Request, context: RouteContext) {
  const current = identity(request);
  if (!current) return json({ error: "Sign in with ChatGPT to continue" }, { status: 401 });
  const { id } = await context.params;
  if (!validAttachmentId(id)) return json({ error: "A valid attachment id is required" }, { status: 400 });
  await initializeDatabase();
  const row = await attachmentForUser(id, current.userId);
  if (!row || row.owner_id !== current.userId) return json({ error: "Attachment not found" }, { status: 404 });
  await Promise.all([mediaBucket().delete(row.object_key), row.thumbnail_object_key ? mediaBucket().delete(row.thumbnail_object_key) : Promise.resolve()]);
  const now = new Date().toISOString();
  await database().prepare("UPDATE attachments SET status = 'deleted', deleted_at = ?, updated_at = ? WHERE id = ?").bind(now, now, id).run();
  return json({ deleted: true });
}
