import { database, type D1Result } from "./social";

type PushEnv = { VAPID_PUBLIC_KEY?: string; VAPID_PRIVATE_KEY?: string; VAPID_SUBJECT?: string };
type PushSubscriptionRow = { id: string; endpoint: string; p256dh: string; auth: string };
type Subscription = { endpoint: string; keys: { p256dh: string; auth: string } };

const encoder = new TextEncoder();
const pushServiceHosts = ["fcm.googleapis.com", "updates.push.services.mozilla.com", "push.services.mozilla.com", "web.push.apple.com"];

function base64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function join(...parts: Uint8Array[]) {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

async function hmac(keyBytes: Uint8Array, value: Uint8Array) {
  const key = await crypto.subtle.importKey("raw", keyBytes as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, value as BufferSource));
}

async function hkdfExtract(salt: Uint8Array, input: Uint8Array) {
  return hmac(salt, input);
}

async function hkdfExpand(key: Uint8Array, info: Uint8Array, length: number) {
  return (await hmac(key, join(info, new Uint8Array([1])))).slice(0, length);
}

function configuration() {
  const values = process.env as PushEnv;
  const publicKey = values.VAPID_PUBLIC_KEY?.trim();
  const privateKey = values.VAPID_PRIVATE_KEY?.trim();
  const subject = values.VAPID_SUBJECT?.trim();
  if (!publicKey || !privateKey || !subject || (!subject.startsWith("mailto:") && !subject.startsWith("https://"))) return null;
  let publicBytes: Uint8Array;
  let privateBytes: Uint8Array;
  try {
    publicBytes = fromBase64Url(publicKey);
    privateBytes = fromBase64Url(privateKey);
  } catch {
    return null;
  }
  if (publicBytes.length !== 65 || publicBytes[0] !== 4 || privateBytes.length !== 32) return null;
  return { publicKey, publicBytes, privateKey, subject };
}

export function pushPublicKey() {
  return configuration()?.publicKey ?? null;
}

export function validPushSubscription(value: unknown): value is Subscription {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<Subscription>;
  if (typeof candidate.endpoint !== "string" || candidate.endpoint.length > 4_096) return false;
  try {
    const endpoint = new URL(candidate.endpoint);
    if (endpoint.protocol !== "https:" || !pushServiceHosts.includes(endpoint.hostname)) return false;
  } catch { return false; }
  if (typeof candidate.keys?.p256dh !== "string" || typeof candidate.keys.auth !== "string") return false;
  try {
    const publicKey = fromBase64Url(candidate.keys.p256dh);
    return publicKey.length === 65 && publicKey[0] === 4 && fromBase64Url(candidate.keys.auth).length === 16;
  } catch {
    return false;
  }
}

async function vapidJwt(endpoint: string, config: NonNullable<ReturnType<typeof configuration>>) {
  const header = base64Url(encoder.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const payload = base64Url(encoder.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1_000) + 43_200, sub: config.subject })));
  const publicBytes = config.publicBytes;
  const key = await crypto.subtle.importKey("jwk", {
    kty: "EC", crv: "P-256", x: base64Url(publicBytes.slice(1, 33)), y: base64Url(publicBytes.slice(33, 65)), d: config.privateKey, ext: false, key_ops: ["sign"],
  }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, encoder.encode(`${header}.${payload}`)));
  if (signature.length !== 64) throw new Error("VAPID signer returned an invalid ES256 signature");
  return `${header}.${payload}.${base64Url(signature)}`;
}

async function encryptPayload(subscription: Subscription, plaintext: Uint8Array) {
  const clientPublicBytes = fromBase64Url(subscription.keys.p256dh);
  const clientPublicKey = await crypto.subtle.importKey("raw", clientPublicBytes, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const localKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]) as CryptoKeyPair;
  const localPublicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", localKeys.publicKey));
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: clientPublicKey }, localKeys.privateKey, 256));
  const authSecret = fromBase64Url(subscription.keys.auth);
  const keyInfo = join(encoder.encode("WebPush: info\0"), clientPublicBytes, localPublicBytes);
  const authPrk = await hkdfExtract(authSecret, sharedSecret);
  const inputKey = await hkdfExpand(authPrk, keyInfo, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const messagePrk = await hkdfExtract(salt, inputKey);
  const contentKey = await hkdfExpand(messagePrk, encoder.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdfExpand(messagePrk, encoder.encode("Content-Encoding: nonce\0"), 12);
  const aesKey = await crypto.subtle.importKey("raw", contentKey, { name: "AES-GCM", length: 128 }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, join(plaintext, new Uint8Array([2]))));
  const recordSize = new Uint8Array(4);
  new DataView(recordSize.buffer).setUint32(0, 4_096);
  return join(salt, recordSize, new Uint8Array([localPublicBytes.length]), localPublicBytes, ciphertext);
}

async function sendPush(subscription: PushSubscriptionRow, config: NonNullable<ReturnType<typeof configuration>>) {
  const payload = encoder.encode(JSON.stringify({ title: "Whisper", body: "New encrypted message", tag: "whisper-message", url: "/" }));
  const body = await encryptPayload({ endpoint: subscription.endpoint, keys: { p256dh: subscription.p256dh, auth: subscription.auth } }, payload);
  const jwt = await vapidJwt(subscription.endpoint, config);
  return fetch(subscription.endpoint, {
    method: "POST",
    headers: { authorization: `vapid t=${jwt}, k=${config.publicKey}`, "content-encoding": "aes128gcm", "content-type": "application/octet-stream", ttl: "60", urgency: "normal" },
    body,
    signal: AbortSignal.timeout(5_000),
  });
}

export async function sendMessagePushNotifications(conversationId: string, senderId: string) {
  const config = configuration();
  if (!config) return { sent: 0, unavailable: true };
  const result = await database().prepare(
    `SELECT ps.id, ps.endpoint, ps.p256dh, ps.auth FROM push_subscriptions ps
     JOIN conversation_members cm ON cm.user_id = ps.user_id
     WHERE cm.conversation_id = ? AND cm.user_id != ? LIMIT 300`,
  ).bind(conversationId, senderId).all<PushSubscriptionRow>() as D1Result<PushSubscriptionRow>;
  let sent = 0;
  const subscriptions = result.results ?? [];
  for (let index = 0; index < subscriptions.length; index += 20) {
    const outcomes = await Promise.allSettled(subscriptions.slice(index, index + 20).map(async (subscription) => {
      const response = await sendPush(subscription, config);
      if (response.ok) return true;
      if (response.status === 404 || response.status === 410) await database().prepare("DELETE FROM push_subscriptions WHERE id = ?").bind(subscription.id).run();
      return false;
    }));
    sent += outcomes.filter((outcome) => outcome.status === "fulfilled" && outcome.value).length;
  }
  return { sent, unavailable: false };
}
