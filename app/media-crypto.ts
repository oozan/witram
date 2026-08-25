export type MediaKind = "image" | "video" | "gif" | "audio" | "file";
export type MediaRetention = "1d" | "7d" | "30d" | "forever";

export type AttachmentDescriptor = {
  version: 1;
  id: string;
  kind: MediaKind;
  name: string;
  mime: string;
  size: number;
  key: string;
  iv: string;
  thumbnailIv?: string;
  thumbnailMime?: string;
  retention: MediaRetention;
  expiresAt: string | null;
  duration?: number;
};

const MAX_BYTES: Record<MediaKind, number> = {
  image: 15 * 1024 * 1024,
  gif: 15 * 1024 * 1024,
  audio: 25 * 1024 * 1024,
  video: 50 * 1024 * 1024,
  file: 50 * 1024 * 1024,
};

const FILE_MIME_TYPES = new Set([
  "application/pdf", "application/zip", "application/json", "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.ms-excel", "application/vnd.ms-powerpoint", "text/plain", "text/csv",
]);

export function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(binary);
}

export function base64ToBytes(value: string) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function mediaKindFor(file: File): MediaKind | null {
  const mime = file.type.toLowerCase();
  if (mime === "image/gif") return "gif";
  if (["image/jpeg", "image/png", "image/webp"].includes(mime)) return "image";
  if (["video/mp4", "video/webm", "video/quicktime"].includes(mime)) return "video";
  if (["audio/webm", "audio/ogg", "audio/mpeg", "audio/wav", "audio/mp4", "audio/x-m4a"].includes(mime)) return "audio";
  if (FILE_MIME_TYPES.has(mime)) return "file";
  return null;
}

function headerMatches(mime: string, bytes: Uint8Array) {
  const ascii = (start: number, length: number) => String.fromCharCode(...bytes.slice(start, start + length));
  if (mime === "image/jpeg") return bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  if (mime === "image/png") return bytes[0] === 0x89 && ascii(1, 3) === "PNG" && bytes[4] === 0x0d && bytes[5] === 0x0a;
  if (mime === "image/gif") return ascii(0, 6) === "GIF87a" || ascii(0, 6) === "GIF89a";
  if (mime === "image/webp") return ascii(0, 4) === "RIFF" && ascii(8, 4) === "WEBP";
  if (mime === "application/pdf") return ascii(0, 5) === "%PDF-";
  if (mime === "application/zip" || mime.includes("officedocument")) return bytes[0] === 0x50 && bytes[1] === 0x4b;
  if (mime === "video/mp4" || mime === "video/quicktime" || mime === "audio/mp4" || mime === "audio/x-m4a") return ascii(4, 4) === "ftyp";
  if (mime === "video/webm" || mime === "audio/webm") return bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3;
  if (mime === "audio/ogg") return ascii(0, 4) === "OggS";
  if (mime === "audio/wav") return ascii(0, 4) === "RIFF" && ascii(8, 4) === "WAVE";
  if (mime === "audio/mpeg") return (bytes[0] === 0x49 && ascii(0, 3) === "ID3") || (bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0);
  if (mime === "application/msword" || mime === "application/vnd.ms-excel" || mime === "application/vnd.ms-powerpoint") {
    return [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].every((byte, index) => bytes[index] === byte);
  }
  return mime.startsWith("text/") || mime === "application/json";
}

export async function validateMediaFile(file: File) {
  const kind = mediaKindFor(file);
  if (!kind) throw new Error("This file type is not supported. Use JPG, PNG, WebP, GIF, MP4, WebM, common audio, PDF, Office, ZIP, text, CSV, or JSON files.");
  if (file.size < 1) throw new Error("Empty files cannot be uploaded");
  if (file.size > MAX_BYTES[kind]) throw new Error(`${kind === "image" || kind === "gif" ? "Images and GIFs" : kind === "audio" ? "Audio" : "Videos and files"} can be up to ${MAX_BYTES[kind] / 1024 / 1024} MB`);
  const header = new Uint8Array(await file.slice(0, 16).arrayBuffer());
  if (!headerMatches(file.type.toLowerCase(), header)) throw new Error("The file contents do not match the declared file type");
  return kind;
}

export function createMediaKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function encryptMediaBlob(blob: Blob, keyBytes: Uint8Array) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes as BufferSource, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, await blob.arrayBuffer());
  return { ciphertext: new Blob([ciphertext], { type: "application/octet-stream" }), iv };
}

export async function decryptMediaBlob(ciphertext: ArrayBuffer, keyValue: string, ivValue: string, mime: string) {
  const key = await crypto.subtle.importKey("raw", base64ToBytes(keyValue) as BufferSource, "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(ivValue) as BufferSource }, key, ciphertext);
  return new Blob([plaintext], { type: mime });
}

async function imageThumbnail(file: File) {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, 360 / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(bitmap.width * scale));
  canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  canvas.getContext("2d")?.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close();
  return await new Promise<Blob>((resolve, reject) => canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error("Thumbnail generation failed")), "image/webp", 0.72));
}

async function videoThumbnail(file: File) {
  const url = URL.createObjectURL(file);
  try {
    const video = document.createElement("video");
    video.preload = "metadata";
    video.muted = true;
    video.src = url;
    await new Promise<void>((resolve, reject) => {
      const timer = window.setTimeout(() => reject(new Error("Video preview timed out")), 8_000);
      video.onloadeddata = () => { window.clearTimeout(timer); resolve(); };
      video.onerror = () => { window.clearTimeout(timer); reject(new Error("Video preview could not be read")); };
    });
    const scale = Math.min(1, 360 / Math.max(video.videoWidth, video.videoHeight));
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(video.videoWidth * scale));
    canvas.height = Math.max(1, Math.round(video.videoHeight * scale));
    canvas.getContext("2d")?.drawImage(video, 0, 0, canvas.width, canvas.height);
    return await new Promise<Blob>((resolve, reject) => canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error("Video thumbnail generation failed")), "image/webp", 0.72));
  } finally {
    URL.revokeObjectURL(url);
  }
}

export async function createEncryptedThumbnail(file: File, kind: MediaKind, keyBytes: Uint8Array) {
  if (kind !== "image" && kind !== "gif" && kind !== "video") return null;
  const thumbnail = kind === "video" ? await videoThumbnail(file) : await imageThumbnail(file);
  if (thumbnail.size > 580 * 1024) throw new Error("The generated encrypted thumbnail is too large");
  const encrypted = await encryptMediaBlob(thumbnail, keyBytes);
  return { ...encrypted, mime: "image/webp" };
}

export function isAttachmentDescriptor(value: unknown): value is AttachmentDescriptor {
  if (!value || typeof value !== "object") return false;
  const item = value as Record<string, unknown>;
  return item.version === 1 && typeof item.id === "string" && typeof item.name === "string" && typeof item.mime === "string"
    && typeof item.size === "number" && typeof item.key === "string" && typeof item.iv === "string"
    && typeof item.retention === "string" && (typeof item.expiresAt === "string" || item.expiresAt === null)
    && ["image", "video", "gif", "audio", "file"].includes(String(item.kind));
}
