"use client";

import {
  createApplicationMessage,
  createCommit,
  createGroup,
  decodeGroupState,
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  encodeGroupState,
  encodeMlsMessage,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  processPrivateMessage,
  processPublicMessage,
  zeroOutUint8Array,
  type ClientState,
  type KeyPackage,
  type PrivateKeyPackage,
  type Proposal,
} from "ts-mls";
import { defaultClientConfig } from "ts-mls/clientConfig.js";
import { verifyKeyPackage } from "ts-mls/keyPackage.js";
import { decodeRatchetTree, encodeRatchetTree } from "ts-mls/ratchetTree.js";

const DATABASE_NAME = "whisper-mls-v1";
const CIPHERSUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" as const;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const conversationQueues = new Map<string, Promise<void>>();

type CurrentUser = { id: string; email: string; displayName: string };
type KeyPackageRecord = { version: number; publicPackage: Uint8Array; privatePackage: PrivateKeyPackage; createdAt: string };
type DeviceRecord = {
  key: string;
  deviceId: string;
  userId: string;
  name: string;
  userIdentityPublicKey: Uint8Array;
  userIdentityPrivateKey: CryptoKey;
  deviceIdentityPublicKey: Uint8Array;
  deviceIdentityPrivateKey: CryptoKey;
  deviceIdentitySignature: Uint8Array;
  packages: KeyPackageRecord[];
};
type SessionRecord = { conversationId: string; deviceKey: string; state: Uint8Array; lastEventId: string | null; verifiedSafetyNumber: string | null; updatedAt: string };
type CachedMessage = { id: string; conversationId: string; content: string };
type DirectoryDevice = { id: string; name: string; identityPublicKey: string; identitySignature: string; keyPackage: string; keyPackageSignature: string; keyPackageVersion: number };
type KeyDirectory = { userId: string; identityPublicKey: string | null; devices: DirectoryDevice[]; error?: string };

async function serializeConversation<T>(conversationId: string, operation: () => Promise<T>) {
  const previous = conversationQueues.get(conversationId) ?? Promise.resolve();
  const current = previous.catch(() => undefined).then(operation);
  const tail = current.then(() => undefined, () => undefined);
  conversationQueues.set(conversationId, tail);
  try {
    return await current;
  } finally {
    if (conversationQueues.get(conversationId) === tail) conversationQueues.delete(conversationId);
  }
}

function openDatabase() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("device")) db.createObjectStore("device", { keyPath: "key" });
      if (!db.objectStoreNames.contains("sessions")) db.createObjectStore("sessions", { keyPath: "conversationId" });
      if (!db.objectStoreNames.contains("messages")) db.createObjectStore("messages", { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("MLS key vault could not be opened"));
  });
}

async function vaultGet<T>(storeName: string, key: string): Promise<T | undefined> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, "readonly");
    const request = transaction.objectStore(storeName).get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error);
    transaction.oncomplete = () => db.close();
  });
}

async function vaultPut(storeName: string, value: unknown) {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(storeName, "readwrite");
    transaction.objectStore(storeName).put(value);
    transaction.oncomplete = () => { db.close(); resolve(); };
    transaction.onerror = () => reject(transaction.error);
  });
}

function toBase64(bytes: Uint8Array) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(binary);
}

function fromBase64(value: string) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function asArrayBuffer(bytes: Uint8Array) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function fingerprint(bytes: Uint8Array) {
  return toBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(bytes))));
}

async function generateNonExportableSigningKey() {
  const generated = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const [publicRaw, privatePkcs8] = await Promise.all([
    crypto.subtle.exportKey("raw", generated.publicKey),
    crypto.subtle.exportKey("pkcs8", generated.privateKey),
  ]);
  const privateBytes = new Uint8Array(privatePkcs8);
  const privateKey = await crypto.subtle.importKey("pkcs8", asArrayBuffer(privateBytes), { name: "Ed25519" }, false, ["sign"]);
  privateBytes.fill(0);
  return { publicKey: new Uint8Array(publicRaw), privateKey };
}

async function sign(privateKey: CryptoKey, value: Uint8Array) {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, asArrayBuffer(value)));
}

async function verify(publicKey: Uint8Array, signature: Uint8Array, value: Uint8Array) {
  const key = await crypto.subtle.importKey("raw", asArrayBuffer(publicKey), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, asArrayBuffer(signature), asArrayBuffer(value));
}

async function suite() {
  return getCiphersuiteImpl(getCiphersuiteFromName(CIPHERSUITE));
}

async function makeKeyPackage(user: CurrentUser, deviceId: string, userPublic: Uint8Array, devicePublic: Uint8Array, version: number) {
  const credential = {
    credentialType: "basic" as const,
    identity: encoder.encode(JSON.stringify({ v: 1, userId: user.id, deviceId, userKey: await fingerprint(userPublic), deviceKey: await fingerprint(devicePublic) })),
  };
  const generated = await generateKeyPackage(credential, defaultCapabilities(), defaultLifetime, [], await suite());
  return { version, publicPackage: encodeMlsMessage({ wireformat: "mls_key_package", version: "mls10", keyPackage: generated.publicPackage }), privatePackage: generated.privatePackage, createdAt: new Date().toISOString() };
}

async function publishDevice(device: DeviceRecord) {
  const currentPackage = device.packages.at(-1)!;
  const packageSignature = await sign(device.deviceIdentityPrivateKey, currentPackage.publicPackage);
  const response = await fetch("/api/keys", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      deviceId: device.deviceId,
      name: device.name,
      userIdentityPublicKey: toBase64(device.userIdentityPublicKey),
      deviceIdentityPublicKey: toBase64(device.deviceIdentityPublicKey),
      deviceIdentitySignature: toBase64(device.deviceIdentitySignature),
      keyPackage: toBase64(currentPackage.publicPackage),
      keyPackageSignature: toBase64(packageSignature),
      keyPackageVersion: currentPackage.version,
    }),
  });
  const payload = await response.json() as { error?: string };
  if (!response.ok) throw new Error(payload.error ?? "MLS device registration failed");
}

export async function ensureMlsDevice(user: CurrentUser) {
  const deviceKey = `user:${user.id}`;
  const existing = await vaultGet<DeviceRecord>("device", deviceKey);
  if (existing?.userId === user.id) {
    await publishDevice(existing);
    return existing;
  }

  const [userIdentity, deviceIdentity] = await Promise.all([generateNonExportableSigningKey(), generateNonExportableSigningKey()]);
  const deviceId = crypto.randomUUID();
  const binding = encoder.encode(`whisper-device-v1:${user.id}:${deviceId}:${toBase64(deviceIdentity.publicKey)}`);
  const firstPackage = await makeKeyPackage(user, deviceId, userIdentity.publicKey, deviceIdentity.publicKey, 1);
  const device: DeviceRecord = {
    key: deviceKey,
    deviceId,
    userId: user.id,
    name: `${navigator.platform || "Browser"} · Whisper Web`,
    userIdentityPublicKey: userIdentity.publicKey,
    userIdentityPrivateKey: userIdentity.privateKey,
    deviceIdentityPublicKey: deviceIdentity.publicKey,
    deviceIdentityPrivateKey: deviceIdentity.privateKey,
    deviceIdentitySignature: await sign(userIdentity.privateKey, binding),
    packages: [firstPackage],
  };
  await vaultPut("device", device);
  await publishDevice(device);
  return device;
}

async function rotatePublishedKeyPackage(user: CurrentUser, device: DeviceRecord) {
  const version = device.packages.at(-1)!.version + 1;
  const nextPackage = await makeKeyPackage(user, device.deviceId, device.userIdentityPublicKey, device.deviceIdentityPublicKey, version);
  const updated = { ...device, packages: [...device.packages.slice(-8), nextPackage] };
  await vaultPut("device", updated);
  await publishDevice(updated);
  return updated;
}

async function getDirectory(userId: string): Promise<KeyDirectory> {
  const response = await fetch(`/api/keys?userId=${encodeURIComponent(userId)}`);
  const payload = await response.json() as KeyDirectory;
  if (!response.ok) throw new Error(payload.error ?? "Identity directory lookup failed");
  return payload;
}

async function verifiedKeyPackage(directory: KeyDirectory, device: DirectoryDevice): Promise<KeyPackage> {
  if (!directory.identityPublicKey) throw new Error("Contact has not registered an MLS identity key");
  const userPublic = fromBase64(directory.identityPublicKey);
  const devicePublic = fromBase64(device.identityPublicKey);
  const binding = encoder.encode(`whisper-device-v1:${directory.userId}:${device.id}:${device.identityPublicKey}`);
  if (!await verify(userPublic, fromBase64(device.identitySignature), binding)) throw new Error("Contact device identity could not be authenticated");
  const keyPackageBytes = fromBase64(device.keyPackage);
  if (!await verify(devicePublic, fromBase64(device.keyPackageSignature), keyPackageBytes)) throw new Error("Contact MLS key package could not be authenticated");
  const decoded = decodeMlsMessage(keyPackageBytes, 0)?.[0];
  if (!decoded || decoded.wireformat !== "mls_key_package" || decoded.keyPackage.leafNode.credential.credentialType !== "basic") throw new Error("Contact MLS key package is invalid");
  if (!await verifyKeyPackage(decoded.keyPackage, (await suite()).signature)) throw new Error("Contact MLS key package signature is invalid");
  const credential = JSON.parse(decoder.decode(decoded.keyPackage.leafNode.credential.identity)) as { userId?: string; deviceId?: string; userKey?: string; deviceKey?: string };
  if (credential.userId !== directory.userId || credential.deviceId !== device.id || credential.userKey !== await fingerprint(userPublic) || credential.deviceKey !== await fingerprint(devicePublic)) throw new Error("Contact MLS credential does not match the identity directory");
  return decoded.keyPackage;
}

function decodeOwnPackage(record: KeyPackageRecord) {
  const decoded = decodeMlsMessage(record.publicPackage, 0)?.[0];
  if (!decoded || decoded.wireformat !== "mls_key_package") throw new Error("Local MLS key package is invalid");
  return decoded.keyPackage;
}

async function saveSession(conversationId: string, state: ClientState, previous?: SessionRecord, deviceKey?: string) {
  const session: SessionRecord = {
    conversationId,
    deviceKey: previous?.deviceKey ?? deviceKey ?? "",
    state: encodeGroupState(state),
    lastEventId: previous?.lastEventId ?? null,
    verifiedSafetyNumber: previous?.verifiedSafetyNumber ?? null,
    updatedAt: new Date().toISOString(),
  };
  await vaultPut("sessions", session);
  return session;
}

function decodeSession(record: SessionRecord) {
  const decoded = decodeGroupState(record.state, 0)?.[0];
  if (!decoded) throw new Error("Local MLS session is invalid");
  return { ...decoded, clientConfig: defaultClientConfig } as ClientState;
}

export async function createMlsConversation(user: CurrentUser, conversationId: string, memberUserIds: string[]) {
  if (!memberUserIds.length) throw new Error("An MLS conversation needs another member");
  let device = await ensureMlsDevice(user);
  const ownPackage = device.packages.at(-1)!;
  let state = await createGroup(encoder.encode(conversationId), decodeOwnPackage(ownPackage), ownPackage.privatePackage, [], await suite());
  const recipients: Array<{ userId: string; device: DirectoryDevice; keyPackage: KeyPackage }> = [];
  for (const memberUserId of memberUserIds) {
    const directory = await getDirectory(memberUserId);
    if (!directory.devices.length) throw new Error("Contact must open Whisper once to publish an MLS device key");
    for (const peerDevice of directory.devices) recipients.push({ userId: memberUserId, device: peerDevice, keyPackage: await verifiedKeyPackage(directory, peerDevice) });
  }
  const proposals: Proposal[] = recipients.map((recipient) => ({ proposalType: "add", add: { keyPackage: recipient.keyPackage } }));
  const commit = await createCommit({ state, cipherSuite: await suite() }, { extraProposals: proposals, ratchetTreeExtension: true });
  state = commit.newState;
  commit.consumed.forEach(zeroOutUint8Array);
  if (!commit.welcome) throw new Error("MLS did not produce a welcome for the new members");
  const welcome = toBase64(encodeMlsMessage({ wireformat: "mls_welcome", version: "mls10", welcome: commit.welcome }));
  const ratchetTree = toBase64(encodeRatchetTree(state.ratchetTree));
  for (const recipient of recipients) {
    const response = await fetch("/api/mls/welcomes", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ conversationId, recipientUserId: recipient.userId, recipientDeviceId: recipient.device.id, recipientKeyPackageVersion: recipient.device.keyPackageVersion, senderDeviceId: device.deviceId, welcome, ratchetTree }) });
    const payload = await response.json() as { error?: string };
    if (!response.ok) throw new Error(payload.error ?? "MLS welcome delivery failed");
  }
  await saveSession(conversationId, state, undefined, device.key);
  device = await rotatePublishedKeyPackage(user, device);
  return { ready: true, epoch: Number(state.groupContext.epoch), deviceId: device.deviceId };
}

export async function joinMlsConversation(user: CurrentUser, conversationId: string) {
  const existing = await vaultGet<SessionRecord>("sessions", conversationId);
  if (existing) return { ready: true, epoch: Number(decodeSession(existing).groupContext.epoch) };
  let device = await ensureMlsDevice(user);
  const response = await fetch(`/api/mls/welcomes?conversationId=${encodeURIComponent(conversationId)}&deviceId=${encodeURIComponent(device.deviceId)}`);
  const payload = await response.json() as { welcomes?: Array<{ id: string; recipientKeyPackageVersion: number; welcome: string; ratchetTree: string }>; error?: string };
  if (!response.ok) throw new Error(payload.error ?? "MLS welcome lookup failed");
  const welcomeRecord = payload.welcomes?.[0];
  if (!welcomeRecord) return { ready: false, epoch: null };
  const keyPackage = device.packages.find((candidate) => candidate.version === welcomeRecord.recipientKeyPackageVersion);
  if (!keyPackage) throw new Error("This MLS welcome targets an unavailable one-time key package");
  const decodedWelcome = decodeMlsMessage(fromBase64(welcomeRecord.welcome), 0)?.[0];
  const decodedTree = decodeRatchetTree(fromBase64(welcomeRecord.ratchetTree), 0)?.[0];
  if (!decodedWelcome || decodedWelcome.wireformat !== "mls_welcome" || !decodedTree) throw new Error("MLS welcome data is invalid");
  const state = await joinGroup(decodedWelcome.welcome, decodeOwnPackage(keyPackage), keyPackage.privatePackage, emptyPskIndex, await suite(), decodedTree);
  await saveSession(conversationId, state, undefined, device.key);
  const claim = await fetch("/api/mls/welcomes", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ welcomeId: welcomeRecord.id, deviceId: device.deviceId }) });
  if (!claim.ok) throw new Error("MLS welcome could not be marked as claimed");
  device = await rotatePublishedKeyPackage(user, device);
  return { ready: true, epoch: Number(state.groupContext.epoch), deviceId: device.deviceId };
}

async function syncMlsEventsUnlocked(conversationId: string, deviceId: string, throughEpoch?: number) {
  const record = await vaultGet<SessionRecord>("sessions", conversationId);
  if (!record) return false;
  let state = decodeSession(record);
  const response = await fetch(`/api/mls/events?conversationId=${encodeURIComponent(conversationId)}${record.lastEventId ? `&after=${encodeURIComponent(record.lastEventId)}` : ""}`);
  const payload = await response.json() as { events?: Array<{ id: string; senderDeviceId: string; payload: string; epoch: number }>; error?: string };
  if (!response.ok) throw new Error(payload.error ?? "MLS epoch synchronization failed");
  let lastEventId = record.lastEventId;
  for (const event of payload.events ?? []) {
    if (throughEpoch !== undefined && event.epoch > throughEpoch) break;
    lastEventId = event.id;
    if (event.senderDeviceId === deviceId) continue;
    const decoded = decodeMlsMessage(fromBase64(event.payload), 0)?.[0];
    if (!decoded || decoded.wireformat !== "mls_public_message") throw new Error("MLS commit event is invalid");
    const processed = await processPublicMessage(state, decoded.publicMessage, emptyPskIndex, await suite());
    state = processed.newState;
    processed.consumed.forEach(zeroOutUint8Array);
  }
  await vaultPut("sessions", { ...record, state: encodeGroupState(state), lastEventId, updatedAt: new Date().toISOString() });
  return true;
}

export function syncMlsEvents(conversationId: string, deviceId: string, throughEpoch?: number) {
  return serializeConversation(conversationId, () => syncMlsEventsUnlocked(conversationId, deviceId, throughEpoch));
}

export function encryptMlsMessage(conversationId: string, content: string, localId: string) {
  return serializeConversation(conversationId, async () => {
  const record = await vaultGet<SessionRecord>("sessions", conversationId);
  if (!record) throw new Error("MLS session is not ready");
  const device = await vaultGet<DeviceRecord>("device", record.deviceKey);
  if (!device) throw new Error("MLS device is unavailable");
  await syncMlsEventsUnlocked(conversationId, device.deviceId);
  const refreshed = await vaultGet<SessionRecord>("sessions", conversationId);
  const encrypted = await createApplicationMessage(decodeSession(refreshed ?? record), encoder.encode(content), await suite());
  encrypted.consumed.forEach(zeroOutUint8Array);
  await saveSession(conversationId, encrypted.newState, refreshed ?? record);
  await vaultPut("messages", { id: localId, conversationId, content } satisfies CachedMessage);
  return { ciphertext: toBase64(encodeMlsMessage({ wireformat: "mls_private_message", version: "mls10", privateMessage: encrypted.privateMessage })), protocol: "mls-rfc9420-v1", epoch: Number(encrypted.newState.groupContext.epoch), senderDeviceId: device.deviceId };
  });
}

export async function cacheSentMlsMessage(localId: string, serverId: string, conversationId: string) {
  const cached = await vaultGet<CachedMessage>("messages", localId);
  if (cached) await vaultPut("messages", { id: serverId, conversationId, content: cached.content } satisfies CachedMessage);
}

export function decryptMlsMessage(conversationId: string, message: { id: string; ciphertext: string; mine: boolean }) {
  return serializeConversation(conversationId, async () => {
  const cached = await vaultGet<CachedMessage>("messages", message.id);
  if (cached) return cached.content;
  if (message.mine) return null;
  const record = await vaultGet<SessionRecord>("sessions", conversationId);
  if (!record) return null;
  const decoded = decodeMlsMessage(fromBase64(message.ciphertext), 0)?.[0];
  if (!decoded || decoded.wireformat !== "mls_private_message") throw new Error("MLS application message is invalid");
  const processed = await processPrivateMessage(decodeSession(record), decoded.privateMessage, emptyPskIndex, await suite());
  processed.consumed.forEach(zeroOutUint8Array);
  await saveSession(conversationId, processed.newState, record);
  if (processed.kind !== "applicationMessage") return null;
  const content = decoder.decode(processed.message);
  await vaultPut("messages", { id: message.id, conversationId, content } satisfies CachedMessage);
  return content;
  });
}

export function rotateMlsEpoch(conversationId: string) {
  return serializeConversation(conversationId, async () => {
  const record = await vaultGet<SessionRecord>("sessions", conversationId);
  if (!record) throw new Error("MLS session is not ready");
  const device = await vaultGet<DeviceRecord>("device", record.deviceKey);
  if (!device) throw new Error("MLS device is unavailable");
  await syncMlsEventsUnlocked(conversationId, device.deviceId);
  const refreshed = await vaultGet<SessionRecord>("sessions", conversationId);
  const commit = await createCommit({ state: decodeSession(refreshed!), cipherSuite: await suite() }, { wireAsPublicMessage: true, ratchetTreeExtension: true });
  commit.consumed.forEach(zeroOutUint8Array);
  const eventPayload = toBase64(encodeMlsMessage(commit.commit));
  const epoch = Number(commit.newState.groupContext.epoch);
  const response = await fetch("/api/mls/events", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ conversationId, senderDeviceId: device.deviceId, kind: "commit", payload: eventPayload, epoch }) });
  const payload = await response.json() as { event?: { id: string }; error?: string };
  if (!response.ok || !payload.event) throw new Error(payload.error ?? "MLS key rotation failed");
  await vaultPut("sessions", { ...refreshed, state: encodeGroupState(commit.newState), lastEventId: payload.event.id, updatedAt: new Date().toISOString() });
  return epoch;
  });
}

export async function getSafetyNumber(user: CurrentUser, peerUserId: string) {
  const device = await ensureMlsDevice(user);
  const directory = await getDirectory(peerUserId);
  if (!directory.identityPublicKey) return null;
  const identities = [toBase64(device.userIdentityPublicKey), directory.identityPublicKey].sort().join(":");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(encoder.encode(`whisper-safety-v1:${identities}`))));
  const groups: string[] = [];
  for (let index = 0; index < 30; index += 2) groups.push((((digest[index] << 8) | digest[index + 1]) % 100000).toString().padStart(5, "0"));
  return groups.join(" ");
}

export async function markSafetyNumberVerified(conversationId: string, safetyNumber: string) {
  const record = await vaultGet<SessionRecord>("sessions", conversationId);
  if (!record) throw new Error("MLS session is not ready");
  await vaultPut("sessions", { ...record, verifiedSafetyNumber: safetyNumber, updatedAt: new Date().toISOString() });
}

export async function getMlsSessionStatus(conversationId: string) {
  const record = await vaultGet<SessionRecord>("sessions", conversationId);
  if (!record) return { ready: false, epoch: null, verified: false };
  const state = decodeSession(record);
  return { ready: true, epoch: Number(state.groupContext.epoch), verified: Boolean(record.verifiedSafetyNumber) };
}
