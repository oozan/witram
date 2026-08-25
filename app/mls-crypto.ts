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
import { getGroupMembers } from "ts-mls/clientState.js";
import { verifyKeyPackage } from "ts-mls/keyPackage.js";
import { decodeRatchetTree, encodeRatchetTree } from "ts-mls/ratchetTree.js";
import { findLeafIndex } from "ts-mls/ratchetTree.js";

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
  userIdentityPrivateBackup?: { ciphertext: Uint8Array; iv: Uint8Array };
  localWrappingKey?: CryptoKey;
  recoverySecret?: Uint8Array;
  deviceIdentityPublicKey: Uint8Array;
  deviceIdentityPrivateKey: CryptoKey;
  deviceIdentitySignature: Uint8Array;
  packages: KeyPackageRecord[];
};
type SessionRecord = { conversationId: string; deviceKey: string; state: Uint8Array; lastEventId: string | null; verifiedSafetyNumber: string | null; updatedAt: string };
type CachedMessage = { id: string; conversationId: string; content: string };
type DirectoryPackage = { version: number; keyPackage: string; keyPackageSignature: string };
type DirectoryDevice = { id: string; name: string; identityPublicKey: string; identitySignature: string; keyPackage: string; keyPackageSignature: string; keyPackageVersion: number; keyPackages?: DirectoryPackage[]; updatedAt?: string };
type KeyDirectory = { userId: string; identityPublicKey: string | null; devices: DirectoryDevice[]; error?: string };
type LinkRequesterRecord = { key: string; userId: string; linkId: string; secret: Uint8Array; privateKey: CryptoKey; publicKey: Uint8Array; expiresAt: string };
type LinkApproverRecord = { key: string; userId: string; linkId: string; secret: Uint8Array; privateKey: CryptoKey; requesterPublicKey: Uint8Array; approverPublicKey: Uint8Array; confirmation: string };

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
    const request = indexedDB.open(DATABASE_NAME, 2);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("device")) db.createObjectStore("device", { keyPath: "key" });
      if (!db.objectStoreNames.contains("sessions")) db.createObjectStore("sessions", { keyPath: "conversationId" });
      if (!db.objectStoreNames.contains("messages")) db.createObjectStore("messages", { keyPath: "id" });
      if (!db.objectStoreNames.contains("links")) db.createObjectStore("links", { keyPath: "key" });
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

async function vaultGetAll<T>(storeName: string): Promise<T[]> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, "readonly");
    const request = transaction.objectStore(storeName).getAll();
    request.onsuccess = () => resolve(request.result as T[]);
    request.onerror = () => reject(request.error);
    transaction.oncomplete = () => db.close();
  });
}

async function vaultDelete(storeName: string, key: string) {
  const db = await openDatabase();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(storeName, "readwrite");
    transaction.objectStore(storeName).delete(key);
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

function toHex(bytes: Uint8Array) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string) {
  if (!/^[a-f0-9]+$/i.test(value) || value.length % 2) throw new Error("Security code is invalid");
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16));
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

async function wrapPrivateSigningKey(privateBytes: Uint8Array, wrappingKey?: CryptoKey) {
  const key = wrappingKey ?? await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asArrayBuffer(iv) }, key, asArrayBuffer(privateBytes)));
  return { wrappingKey: key, backup: { ciphertext, iv } };
}

async function generateTransferableSigningKey() {
  const generated = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const [publicRaw, privatePkcs8] = await Promise.all([crypto.subtle.exportKey("raw", generated.publicKey), crypto.subtle.exportKey("pkcs8", generated.privateKey)]);
  const privateBytes = new Uint8Array(privatePkcs8);
  const privateKey = await crypto.subtle.importKey("pkcs8", asArrayBuffer(privateBytes), { name: "Ed25519" }, false, ["sign"]);
  const wrapped = await wrapPrivateSigningKey(privateBytes);
  privateBytes.fill(0);
  return { publicKey: new Uint8Array(publicRaw), privateKey, privateBackup: wrapped.backup, wrappingKey: wrapped.wrappingKey };
}

async function unwrapUserPrivateKey(device: DeviceRecord) {
  if (!device.userIdentityPrivateBackup || !device.localWrappingKey) throw new Error("Enable recovery on this legacy device before linking or backing up");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: asArrayBuffer(device.userIdentityPrivateBackup.iv) }, device.localWrappingKey, asArrayBuffer(device.userIdentityPrivateBackup.ciphertext)));
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

async function publishDevice(device: DeviceRecord, identityRotationSignature?: Uint8Array) {
  const currentPackage = device.packages.at(-1)!;
  const signedPackages = await Promise.all(device.packages.slice(-24).map(async (item) => ({
    version: item.version,
    keyPackage: toBase64(item.publicPackage),
    keyPackageSignature: toBase64(await sign(device.deviceIdentityPrivateKey, item.publicPackage)),
  })));
  const packageSignature = signedPackages.at(-1)!.keyPackageSignature;
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
      keyPackageSignature: packageSignature,
      keyPackageVersion: currentPackage.version,
      keyPackages: signedPackages,
      identityRotationSignature: identityRotationSignature ? toBase64(identityRotationSignature) : undefined,
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

  const directory = await getDirectory(user.id);
  if (directory.identityPublicKey || directory.devices.length) throw new Error("This account already has encrypted devices. Link this browser or restore a recovery backup.");

  const [userIdentity, deviceIdentity] = await Promise.all([generateTransferableSigningKey(), generateNonExportableSigningKey()]);
  const deviceId = crypto.randomUUID();
  const binding = encoder.encode(`whisper-device-v1:${user.id}:${deviceId}:${toBase64(deviceIdentity.publicKey)}`);
  const packages: KeyPackageRecord[] = [];
  for (let version = 1; version <= 8; version += 1) packages.push(await makeKeyPackage(user, deviceId, userIdentity.publicKey, deviceIdentity.publicKey, version));
  const device: DeviceRecord = {
    key: deviceKey,
    deviceId,
    userId: user.id,
    name: `${navigator.platform || "Browser"} · Whisper Web`,
    userIdentityPublicKey: userIdentity.publicKey,
    userIdentityPrivateKey: userIdentity.privateKey,
    userIdentityPrivateBackup: userIdentity.privateBackup,
    localWrappingKey: userIdentity.wrappingKey,
    deviceIdentityPublicKey: deviceIdentity.publicKey,
    deviceIdentityPrivateKey: deviceIdentity.privateKey,
    deviceIdentitySignature: await sign(userIdentity.privateKey, binding),
    packages,
  };
  await vaultPut("device", device);
  await publishDevice(device);
  return device;
}

async function rotatePublishedKeyPackage(user: CurrentUser, device: DeviceRecord) {
  const version = device.packages.at(-1)!.version + 1;
  const nextPackage = await makeKeyPackage(user, device.deviceId, device.userIdentityPublicKey, device.deviceIdentityPublicKey, version);
  const updated = { ...device, packages: [...device.packages, nextPackage] };
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

function availablePackages(device: DirectoryDevice): DirectoryPackage[] {
  return device.keyPackages?.length ? device.keyPackages : [{ version: device.keyPackageVersion, keyPackage: device.keyPackage, keyPackageSignature: device.keyPackageSignature }];
}

async function verifiedKeyPackage(directory: KeyDirectory, device: DirectoryDevice, selected = availablePackages(device)[0]): Promise<KeyPackage> {
  if (!directory.identityPublicKey) throw new Error("Contact has not registered an MLS identity key");
  const userPublic = fromBase64(directory.identityPublicKey);
  const devicePublic = fromBase64(device.identityPublicKey);
  const binding = encoder.encode(`whisper-device-v1:${directory.userId}:${device.id}:${device.identityPublicKey}`);
  if (!await verify(userPublic, fromBase64(device.identitySignature), binding)) throw new Error("Contact device identity could not be authenticated");
  if (!selected) throw new Error("Contact has no available MLS key package");
  const keyPackageBytes = fromBase64(selected.keyPackage);
  if (!await verify(devicePublic, fromBase64(selected.keyPackageSignature), keyPackageBytes)) throw new Error("Contact MLS key package could not be authenticated");
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
  const recipients: Array<{ userId: string; device: DirectoryDevice; packageVersion: number; keyPackage: KeyPackage }> = [];
  for (const memberUserId of memberUserIds) {
    const directory = await getDirectory(memberUserId);
    if (!directory.devices.length) throw new Error("Contact must open Whisper once to publish an MLS device key");
    for (const peerDevice of directory.devices) {
      const selected = availablePackages(peerDevice)[0];
      if (selected) recipients.push({ userId: memberUserId, device: peerDevice, packageVersion: selected.version, keyPackage: await verifiedKeyPackage(directory, peerDevice, selected) });
    }
  }
  const proposals: Proposal[] = recipients.map((recipient) => ({ proposalType: "add", add: { keyPackage: recipient.keyPackage } }));
  const commit = await createCommit({ state, cipherSuite: await suite() }, { extraProposals: proposals, ratchetTreeExtension: true });
  state = commit.newState;
  commit.consumed.forEach(zeroOutUint8Array);
  if (!commit.welcome) throw new Error("MLS did not produce a welcome for the new members");
  const welcome = toBase64(encodeMlsMessage({ wireformat: "mls_welcome", version: "mls10", welcome: commit.welcome }));
  const ratchetTree = toBase64(encodeRatchetTree(state.ratchetTree));
  for (const recipient of recipients) {
    const response = await fetch("/api/mls/welcomes", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ conversationId, recipientUserId: recipient.userId, recipientDeviceId: recipient.device.id, recipientKeyPackageVersion: recipient.packageVersion, senderDeviceId: device.deviceId, welcome, ratchetTree }) });
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
    if (event.epoch <= Number(state.groupContext.epoch)) continue;
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

function leafDeviceId(leaf: ReturnType<typeof getGroupMembers>[number]) {
  if (leaf.credential.credentialType !== "basic") return null;
  try {
    const credential = JSON.parse(decoder.decode(leaf.credential.identity)) as { deviceId?: string };
    return credential.deviceId ?? null;
  } catch {
    return null;
  }
}

async function postCommit(conversationId: string, deviceId: string, commitMessage: Uint8Array, epoch: number) {
  const response = await fetch("/api/mls/events", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ conversationId, senderDeviceId: deviceId, kind: "commit", payload: toBase64(commitMessage), epoch }) });
  const payload = await response.json() as { event?: { id: string }; error?: string };
  if (!response.ok || !payload.event) throw new Error(payload.error ?? "MLS membership commit failed");
  return payload.event.id;
}

export async function provisionDeviceToConversations(user: CurrentUser, targetDeviceId: string) {
  const localDevice = await ensureMlsDevice(user);
  if (localDevice.deviceId === targetDeviceId) return { provisioned: 0, skipped: 0 };
  const sessions = (await vaultGetAll<SessionRecord>("sessions")).filter((record) => record.deviceKey === localDevice.key);
  let provisioned = 0;
  let skipped = 0;
  for (const session of sessions) {
    await serializeConversation(session.conversationId, async () => {
      await syncMlsEventsUnlocked(session.conversationId, localDevice.deviceId);
      const current = await vaultGet<SessionRecord>("sessions", session.conversationId);
      if (!current) return;
      const state = decodeSession(current);
      if (getGroupMembers(state).some((leaf) => leafDeviceId(leaf) === targetDeviceId)) { skipped += 1; return; }
      const directory = await getDirectory(user.id);
      const target = directory.devices.find((item) => item.id === targetDeviceId);
      const selected = target ? availablePackages(target)[0] : undefined;
      if (!target || !selected) throw new Error("Linked device has no available one-time MLS key package");
      const keyPackage = await verifiedKeyPackage(directory, target, selected);
      const commit = await createCommit({ state, cipherSuite: await suite() }, { extraProposals: [{ proposalType: "add", add: { keyPackage } }], wireAsPublicMessage: true, ratchetTreeExtension: true });
      commit.consumed.forEach(zeroOutUint8Array);
      if (!commit.welcome) throw new Error("MLS did not produce a device Welcome message");
      const welcome = toBase64(encodeMlsMessage({ wireformat: "mls_welcome", version: "mls10", welcome: commit.welcome }));
      const ratchetTree = toBase64(encodeRatchetTree(commit.newState.ratchetTree));
      const welcomeResponse = await fetch("/api/mls/welcomes", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ conversationId: session.conversationId, recipientUserId: user.id, recipientDeviceId: targetDeviceId, recipientKeyPackageVersion: selected.version, senderDeviceId: localDevice.deviceId, welcome, ratchetTree }) });
      const welcomePayload = await welcomeResponse.json() as { error?: string };
      if (!welcomeResponse.ok) throw new Error(welcomePayload.error ?? "Linked-device Welcome delivery failed");
      const epoch = Number(commit.newState.groupContext.epoch);
      const eventId = await postCommit(session.conversationId, localDevice.deviceId, encodeMlsMessage(commit.commit), epoch);
      await vaultPut("sessions", { ...current, state: encodeGroupState(commit.newState), lastEventId: eventId, updatedAt: new Date().toISOString() });
      provisioned += 1;
    });
  }
  return { provisioned, skipped };
}

async function removeDeviceFromAllConversations(targetDeviceId: string) {
  const sessions = await vaultGetAll<SessionRecord>("sessions");
  for (const session of sessions) {
    await serializeConversation(session.conversationId, async () => {
      const localDevice = await vaultGet<DeviceRecord>("device", session.deviceKey);
      if (!localDevice || localDevice.deviceId === targetDeviceId) return;
      await syncMlsEventsUnlocked(session.conversationId, localDevice.deviceId);
      const current = await vaultGet<SessionRecord>("sessions", session.conversationId);
      if (!current) return;
      const state = decodeSession(current);
      const targetLeaf = getGroupMembers(state).find((leaf) => leafDeviceId(leaf) === targetDeviceId);
      if (!targetLeaf) return;
      const leafIndex = findLeafIndex(state.ratchetTree, targetLeaf);
      if (leafIndex === undefined) return;
      const commit = await createCommit({ state, cipherSuite: await suite() }, { extraProposals: [{ proposalType: "remove", remove: { removed: leafIndex } }], wireAsPublicMessage: true, ratchetTreeExtension: true });
      commit.consumed.forEach(zeroOutUint8Array);
      const epoch = Number(commit.newState.groupContext.epoch);
      const eventId = await postCommit(session.conversationId, localDevice.deviceId, encodeMlsMessage(commit.commit), epoch);
      await vaultPut("sessions", { ...current, state: encodeGroupState(commit.newState), lastEventId: eventId, updatedAt: new Date().toISOString() });
    });
  }
}

async function ensureTransferableIdentity(user: CurrentUser) {
  const device = await ensureMlsDevice(user);
  if (device.userIdentityPrivateBackup && device.localWrappingKey) return device;
  const replacement = await generateTransferableSigningKey();
  const rotationBinding = encoder.encode(`whisper-identity-rotation-v1:${user.id}:${toBase64(replacement.publicKey)}`);
  const rotationSignature = await sign(device.userIdentityPrivateKey, rotationBinding);
  const deviceBinding = encoder.encode(`whisper-device-v1:${user.id}:${device.deviceId}:${toBase64(device.deviceIdentityPublicKey)}`);
  const packages: KeyPackageRecord[] = [];
  let version = device.packages.at(-1)?.version ?? 0;
  for (let count = 0; count < 8; count += 1) {
    version += 1;
    packages.push(await makeKeyPackage(user, device.deviceId, replacement.publicKey, device.deviceIdentityPublicKey, version));
  }
  const upgraded: DeviceRecord = {
    ...device,
    userIdentityPublicKey: replacement.publicKey,
    userIdentityPrivateKey: replacement.privateKey,
    userIdentityPrivateBackup: replacement.privateBackup,
    localWrappingKey: replacement.wrappingKey,
    deviceIdentitySignature: await sign(replacement.privateKey, deviceBinding),
    packages,
  };
  await publishDevice(upgraded, rotationSignature);
  await vaultPut("device", upgraded);
  return upgraded;
}

async function linkKey(privateKey: CryptoKey, peerPublicBytes: Uint8Array, secret: Uint8Array) {
  const peer = await crypto.subtle.importKey("raw", asArrayBuffer(peerPublicBytes), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: peer }, privateKey, 256));
  const material = await crypto.subtle.importKey("raw", asArrayBuffer(shared), "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: asArrayBuffer(secret), info: asArrayBuffer(encoder.encode("whisper-device-link-v1")) }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const confirmationBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(new Uint8Array([...shared, ...secret]))));
  shared.fill(0);
  const confirmation = Array.from({ length: 6 }, (_, index) => (((confirmationBytes[index * 2] << 8) | confirmationBytes[index * 2 + 1]) % 10000).toString().padStart(4, "0")).join(" ");
  return { key, confirmation };
}

function normalizeRecoveryCode(value: string) {
  return value.trim().replace(/[\s-]+/g, "");
}

async function recoveryKey(secret: Uint8Array, salt: Uint8Array) {
  const material = await crypto.subtle.importKey("raw", asArrayBuffer(secret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: asArrayBuffer(salt), info: asArrayBuffer(encoder.encode("whisper-encrypted-backup-v1")) }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function beginDeviceLink(user: CurrentUser, requesterName: string) {
  const generated = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", generated.publicKey));
  const secret = crypto.getRandomValues(new Uint8Array(24));
  const codeHash = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(secret)));
  const response = await fetch("/api/devices/links", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ requesterName, requesterPublicKey: toBase64(publicKey), codeHash: toBase64(codeHash) }) });
  const payload = await response.json() as { link?: { id: string; expiresAt: string }; error?: string };
  if (!response.ok || !payload.link) throw new Error(payload.error ?? "Device-link request failed");
  const record: LinkRequesterRecord = { key: `requester:${user.id}`, userId: user.id, linkId: payload.link.id, secret, privateKey: generated.privateKey, publicKey, expiresAt: payload.link.expiresAt };
  await vaultPut("links", record);
  const code = toHex(secret).match(/.{1,4}/g)?.join("-") ?? toHex(secret);
  return { linkId: record.linkId, code, expiresAt: record.expiresAt };
}

export async function inspectDeviceLink(user: CurrentUser) {
  const record = await vaultGet<LinkRequesterRecord>("links", `requester:${user.id}`);
  if (!record) return null;
  const response = await fetch(`/api/devices/links?linkId=${encodeURIComponent(record.linkId)}`);
  const payload = await response.json() as { link?: { status: string; approverPublicKey?: string; encryptedTransfer?: string; transferIv?: string }; error?: string };
  if (!response.ok || !payload.link) throw new Error(payload.error ?? "Device-link request is unavailable");
  let confirmation: string | null = null;
  if (payload.link.approverPublicKey) confirmation = (await linkKey(record.privateKey, fromBase64(payload.link.approverPublicKey), record.secret)).confirmation;
  return { status: payload.link.status, confirmation, ready: payload.link.status === "ready" };
}

export async function acceptDeviceLinkCode(user: CurrentUser, code: string) {
  const secret = fromHex(normalizeRecoveryCode(code));
  if (secret.length !== 24) throw new Error("Device-link code is invalid");
  const codeHash = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(secret)));
  const lookup = await fetch(`/api/devices/links?codeHash=${encodeURIComponent(toBase64(codeHash))}`);
  const payload = await lookup.json() as { link?: { id: string; requesterPublicKey: string }; error?: string };
  if (!lookup.ok || !payload.link) throw new Error(payload.error ?? "Device-link request was not found");
  const generated = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]) as CryptoKeyPair;
  const approverPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", generated.publicKey));
  const offer = await fetch("/api/devices/links", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "offer", linkId: payload.link.id, codeHash: toBase64(codeHash), approverPublicKey: toBase64(approverPublicKey) }) });
  const offered = await offer.json() as { error?: string };
  if (!offer.ok) throw new Error(offered.error ?? "Device-link offer failed");
  const requesterPublicKey = fromBase64(payload.link.requesterPublicKey);
  const derived = await linkKey(generated.privateKey, requesterPublicKey, secret);
  const record: LinkApproverRecord = { key: `approver:${user.id}`, userId: user.id, linkId: payload.link.id, secret, privateKey: generated.privateKey, requesterPublicKey, approverPublicKey, confirmation: derived.confirmation };
  await vaultPut("links", record);
  return { linkId: record.linkId, confirmation: record.confirmation };
}

export async function confirmDeviceLink(user: CurrentUser) {
  const approval = await vaultGet<LinkApproverRecord>("links", `approver:${user.id}`);
  if (!approval) throw new Error("No device-link approval is pending");
  const device = await ensureTransferableIdentity(user);
  const privateBytes = await unwrapUserPrivateKey(device);
  const derived = await linkKey(approval.privateKey, approval.requesterPublicKey, approval.secret);
  const transfer = encoder.encode(JSON.stringify({ v: 1, userId: user.id, userIdentityPublicKey: toBase64(device.userIdentityPublicKey), userIdentityPrivateKey: toBase64(privateBytes), recoverySecret: device.recoverySecret ? toBase64(device.recoverySecret) : null }));
  privateBytes.fill(0);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asArrayBuffer(iv), additionalData: asArrayBuffer(encoder.encode(approval.linkId)) }, derived.key, asArrayBuffer(transfer)));
  transfer.fill(0);
  const codeHash = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(approval.secret)));
  const response = await fetch("/api/devices/links", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "transfer", linkId: approval.linkId, codeHash: toBase64(codeHash), encryptedTransfer: toBase64(ciphertext), transferIv: toBase64(iv) }) });
  const payload = await response.json() as { error?: string };
  if (!response.ok) throw new Error(payload.error ?? "Encrypted device transfer failed");
  await vaultDelete("links", approval.key);
  return { confirmation: approval.confirmation };
}

export async function claimDeviceLink(user: CurrentUser) {
  const request = await vaultGet<LinkRequesterRecord>("links", `requester:${user.id}`);
  if (!request) throw new Error("No device-link request is stored on this browser");
  const response = await fetch(`/api/devices/links?linkId=${encodeURIComponent(request.linkId)}`);
  const payload = await response.json() as { link?: { status: string; approverPublicKey?: string; encryptedTransfer?: string; transferIv?: string }; error?: string };
  if (!response.ok || !payload.link) throw new Error(payload.error ?? "Device-link request is unavailable");
  if (payload.link.status !== "ready" || !payload.link.approverPublicKey || !payload.link.encryptedTransfer || !payload.link.transferIv) throw new Error("The trusted device has not completed the encrypted transfer");
  const derived = await linkKey(request.privateKey, fromBase64(payload.link.approverPublicKey), request.secret);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: asArrayBuffer(fromBase64(payload.link.transferIv)), additionalData: asArrayBuffer(encoder.encode(request.linkId)) }, derived.key, asArrayBuffer(fromBase64(payload.link.encryptedTransfer))));
  const transfer = JSON.parse(decoder.decode(plaintext)) as { v: number; userId: string; userIdentityPublicKey: string; userIdentityPrivateKey: string; recoverySecret?: string | null };
  plaintext.fill(0);
  if (transfer.v !== 1 || transfer.userId !== user.id) throw new Error("Encrypted device transfer belongs to another account");
  const privateBytes = fromBase64(transfer.userIdentityPrivateKey);
  const privateKey = await crypto.subtle.importKey("pkcs8", asArrayBuffer(privateBytes), { name: "Ed25519" }, false, ["sign"]);
  const wrapped = await wrapPrivateSigningKey(privateBytes);
  privateBytes.fill(0);
  const userPublic = fromBase64(transfer.userIdentityPublicKey);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  if (!await verify(userPublic, await sign(privateKey, challenge), challenge)) throw new Error("Transferred account identity is invalid");
  const deviceIdentity = await generateNonExportableSigningKey();
  const deviceId = crypto.randomUUID();
  const binding = encoder.encode(`whisper-device-v1:${user.id}:${deviceId}:${toBase64(deviceIdentity.publicKey)}`);
  const packages: KeyPackageRecord[] = [];
  for (let version = 1; version <= 12; version += 1) packages.push(await makeKeyPackage(user, deviceId, userPublic, deviceIdentity.publicKey, version));
  const device: DeviceRecord = { key: `user:${user.id}`, deviceId, userId: user.id, name: `${navigator.platform || "Browser"} · Whisper Web`, userIdentityPublicKey: userPublic, userIdentityPrivateKey: privateKey, userIdentityPrivateBackup: wrapped.backup, localWrappingKey: wrapped.wrappingKey, recoverySecret: transfer.recoverySecret ? fromBase64(transfer.recoverySecret) : undefined, deviceIdentityPublicKey: deviceIdentity.publicKey, deviceIdentityPrivateKey: deviceIdentity.privateKey, deviceIdentitySignature: await sign(privateKey, binding), packages };
  await publishDevice(device);
  await vaultPut("device", device);
  const codeHash = new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(request.secret)));
  const claim = await fetch("/api/devices/links", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "claim", linkId: request.linkId, codeHash: toBase64(codeHash) }) });
  if (!claim.ok) throw new Error("Linked device could not be finalized");
  await vaultDelete("links", request.key);
  return { deviceId, confirmation: derived.confirmation };
}

export async function createEncryptedBackup(user: CurrentUser) {
  let device = await ensureTransferableIdentity(user);
  const recoverySecret = device.recoverySecret ?? crypto.getRandomValues(new Uint8Array(32));
  if (!device.recoverySecret) {
    device = { ...device, recoverySecret };
    await vaultPut("device", device);
  }
  const privateBytes = await unwrapUserPrivateKey(device);
  const messages: CachedMessage[] = [];
  let backupBytes = 0;
  for (const message of (await vaultGetAll<CachedMessage>("messages")).filter((item) => item.id && item.conversationId).reverse()) {
    const size = encoder.encode(JSON.stringify(message)).byteLength;
    if (backupBytes + size > 1_000_000) break;
    messages.unshift(message);
    backupBytes += size;
  }
  const body = encoder.encode(JSON.stringify({ v: 1, userId: user.id, userIdentityPublicKey: toBase64(device.userIdentityPublicKey), userIdentityPrivateKey: toBase64(privateBytes), messages, createdAt: new Date().toISOString() }));
  privateBytes.fill(0);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await recoveryKey(recoverySecret, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asArrayBuffer(iv), additionalData: asArrayBuffer(encoder.encode(user.id)) }, key, asArrayBuffer(body)));
  body.fill(0);
  const response = await fetch("/api/backups", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ sourceDeviceId: device.deviceId, ciphertext: toBase64(ciphertext), iv: toBase64(iv), salt: toBase64(salt), version: 1 }) });
  const payload = await response.json() as { backup?: { updatedAt: string }; error?: string };
  if (!response.ok) throw new Error(payload.error ?? "Encrypted backup failed");
  return { recoveryCode: toHex(recoverySecret).match(/.{1,4}/g)?.join("-") ?? toHex(recoverySecret), updatedAt: payload.backup?.updatedAt ?? new Date().toISOString() };
}

export async function restoreEncryptedBackup(user: CurrentUser, recoveryCode: string) {
  const response = await fetch("/api/backups");
  const payload = await response.json() as { backup?: { ciphertext: string; iv: string; salt: string } | null; error?: string };
  if (!response.ok || !payload.backup) throw new Error(payload.error ?? "No encrypted backup is available");
  const secret = fromHex(normalizeRecoveryCode(recoveryCode));
  if (secret.length !== 32) throw new Error("Recovery key is invalid");
  const key = await recoveryKey(secret, fromBase64(payload.backup.salt));
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: asArrayBuffer(fromBase64(payload.backup.iv)), additionalData: asArrayBuffer(encoder.encode(user.id)) }, key, asArrayBuffer(fromBase64(payload.backup.ciphertext))));
  } catch {
    throw new Error("Recovery key could not decrypt this backup");
  }
  const backup = JSON.parse(decoder.decode(plaintext)) as { v: number; userId: string; userIdentityPublicKey: string; userIdentityPrivateKey: string; messages?: CachedMessage[] };
  plaintext.fill(0);
  if (backup.v !== 1 || backup.userId !== user.id) throw new Error("Backup belongs to another account");
  const privateBytes = fromBase64(backup.userIdentityPrivateKey);
  const privateKey = await crypto.subtle.importKey("pkcs8", asArrayBuffer(privateBytes), { name: "Ed25519" }, false, ["sign"]);
  const wrapped = await wrapPrivateSigningKey(privateBytes);
  privateBytes.fill(0);
  const userPublic = fromBase64(backup.userIdentityPublicKey);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  if (!await verify(userPublic, await sign(privateKey, challenge), challenge)) throw new Error("Backup identity verification failed");
  const deviceIdentity = await generateNonExportableSigningKey();
  const deviceId = crypto.randomUUID();
  const binding = encoder.encode(`whisper-device-v1:${user.id}:${deviceId}:${toBase64(deviceIdentity.publicKey)}`);
  const packages: KeyPackageRecord[] = [];
  for (let version = 1; version <= 12; version += 1) packages.push(await makeKeyPackage(user, deviceId, userPublic, deviceIdentity.publicKey, version));
  const device: DeviceRecord = { key: `user:${user.id}`, deviceId, userId: user.id, name: `${navigator.platform || "Browser"} · Recovered Whisper Web`, userIdentityPublicKey: userPublic, userIdentityPrivateKey: privateKey, userIdentityPrivateBackup: wrapped.backup, localWrappingKey: wrapped.wrappingKey, recoverySecret: secret, deviceIdentityPublicKey: deviceIdentity.publicKey, deviceIdentityPrivateKey: deviceIdentity.privateKey, deviceIdentitySignature: await sign(privateKey, binding), packages };
  await publishDevice(device);
  await vaultPut("device", device);
  for (const message of backup.messages ?? []) if (message?.id && message.conversationId && typeof message.content === "string") await vaultPut("messages", message);
  const directory = await getDirectory(user.id);
  for (const oldDevice of directory.devices.filter((item) => item.id !== deviceId)) await revokeDevice(user, oldDevice.id);
  return { deviceId, restoredMessages: backup.messages?.length ?? 0 };
}

export async function revokeDevice(user: CurrentUser, deviceId: string) {
  const device = await ensureMlsDevice(user);
  if (device.deviceId === deviceId) throw new Error("Use another linked device to remove this device");
  await removeDeviceFromAllConversations(deviceId);
  const timestamp = new Date().toISOString();
  const signature = await sign(device.userIdentityPrivateKey, encoder.encode(`whisper-device-revoke-v1:${user.id}:${deviceId}:${timestamp}`));
  const response = await fetch("/api/keys", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ deviceId, timestamp, signature: toBase64(signature) }) });
  const payload = await response.json() as { error?: string };
  if (!response.ok) throw new Error(payload.error ?? "Device could not be removed");
}

export async function listAccountDevices(user: CurrentUser) {
  const local = await vaultGet<DeviceRecord>("device", `user:${user.id}`);
  const directory = await getDirectory(user.id);
  const backupResponse = await fetch("/api/backups");
  const backupPayload = await backupResponse.json() as { backup?: { updatedAt: string } | null };
  return { localDeviceId: local?.deviceId ?? null, devices: directory.devices.map((item) => ({ id: item.id, name: item.name, updatedAt: item.updatedAt ?? "", current: item.id === local?.deviceId })), backupUpdatedAt: backupPayload.backup?.updatedAt ?? null, canApproveLinks: Boolean(local) };
}
