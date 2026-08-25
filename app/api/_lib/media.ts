import { database, type D1Result, mediaBucket } from "./social";

export const MEDIA_KINDS = ["image", "video", "gif", "audio", "file"] as const;
export const RETENTION_OPTIONS = ["1d", "7d", "30d", "forever"] as const;

export type MediaKind = typeof MEDIA_KINDS[number];
export type Retention = typeof RETENTION_OPTIONS[number];

export type AttachmentRow = {
  id: string;
  conversation_id: string;
  owner_id: string;
  kind: MediaKind;
  plaintext_size: string;
  ciphertext_size: string;
  thumbnail_ciphertext_size: string | null;
  object_key: string;
  thumbnail_object_key: string | null;
  retention: Retention;
  status: "pending" | "ready" | "deleted";
  expires_at: string | null;
  created_at: string;
};

const MAX_PLAINTEXT_BYTES: Record<MediaKind, number> = {
  image: 15 * 1024 * 1024,
  gif: 15 * 1024 * 1024,
  audio: 25 * 1024 * 1024,
  video: 50 * 1024 * 1024,
  file: 50 * 1024 * 1024,
};

export const MAX_THUMBNAIL_CIPHERTEXT_BYTES = 600 * 1024;

export function isMediaKind(value: unknown): value is MediaKind {
  return typeof value === "string" && MEDIA_KINDS.includes(value as MediaKind);
}

export function isRetention(value: unknown): value is Retention {
  return typeof value === "string" && RETENTION_OPTIONS.includes(value as Retention);
}

export function validAttachmentId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f-]{27,40}$/i.test(value);
}

export function validateMediaSizes(kind: MediaKind, plaintextSize: number, ciphertextSize: number, thumbnailCiphertextSize: number | null) {
  if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 1 || plaintextSize > MAX_PLAINTEXT_BYTES[kind]) return false;
  if (!Number.isSafeInteger(ciphertextSize) || ciphertextSize !== plaintextSize + 16) return false;
  const needsThumbnail = kind === "image" || kind === "video" || kind === "gif";
  if (needsThumbnail && (!thumbnailCiphertextSize || thumbnailCiphertextSize <= 16)) return false;
  if (!needsThumbnail && thumbnailCiphertextSize !== null) return false;
  return thumbnailCiphertextSize === null || (Number.isSafeInteger(thumbnailCiphertextSize) && thumbnailCiphertextSize <= MAX_THUMBNAIL_CIPHERTEXT_BYTES);
}

export function expirationFor(retention: Retention) {
  if (retention === "forever") return null;
  const days = retention === "1d" ? 1 : retention === "7d" ? 7 : 30;
  return new Date(Date.now() + days * 86_400_000).toISOString();
}

export async function conversationMember(conversationId: string, userId: string) {
  return Boolean(await database().prepare(
    "SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ? LIMIT 1",
  ).bind(conversationId, userId).first());
}

export async function attachmentForUser(id: string, userId: string) {
  return await database().prepare(
    `SELECT a.* FROM attachments a
     JOIN conversation_members cm ON cm.conversation_id = a.conversation_id
     WHERE a.id = ? AND cm.user_id = ? LIMIT 1`,
  ).bind(id, userId).first() as AttachmentRow | null;
}

export async function purgeExpiredAttachments(limit = 25) {
  const db = database();
  const result = await db.prepare(
    `SELECT * FROM attachments
     WHERE status != 'deleted' AND (
       (expires_at IS NOT NULL AND expires_at <= ?)
       OR (status = 'pending' AND created_at <= ?)
     )
     ORDER BY COALESCE(expires_at, created_at) ASC LIMIT ?`,
  ).bind(new Date().toISOString(), new Date(Date.now() - 3_600_000).toISOString(), limit).all() as D1Result<AttachmentRow>;
  const rows = result.results ?? [];
  if (!rows.length) return 0;

  const bucket = mediaBucket();
  await Promise.all(rows.flatMap((row) => [bucket.delete(row.object_key), row.thumbnail_object_key ? bucket.delete(row.thumbnail_object_key) : Promise.resolve()]));
  const now = new Date().toISOString();
  await db.batch(rows.map((row) => db.prepare(
    "UPDATE attachments SET status = 'deleted', deleted_at = ?, updated_at = ? WHERE id = ?",
  ).bind(now, now, row.id)));
  return rows.length;
}
