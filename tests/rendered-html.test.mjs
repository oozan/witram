import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render(path = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`http://localhost${path}`, { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the Whisper sign-in boundary for anonymous visitors", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Whisper — Private conversations<\/title>/i);
  assert.match(html, /Welcome to Whisper/);
  assert.match(html, /Sign in with email/);
  assert.match(html, /Continue with Google/);
  assert.match(html, /protected password hash/);
  assert.doesNotMatch(html, /ChatGPT/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape/);
});

test("keeps plaintext out of the persistence boundary", async () => {
  const [route, conversationsRoute, cryptoClient, schema, hosting, social] = await Promise.all([
    readFile(new URL("../app/api/messages/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/conversations/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/client-crypto.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../.openai/hosting.json", import.meta.url), "utf8"),
    readFile(new URL("../app/api/_lib/social.ts", import.meta.url), "utf8"),
  ]);

  assert.match(cryptoClient, /AES-GCM/);
  assert.match(cryptoClient, /indexedDB/);
  assert.match(route, /ciphertext/);
  assert.match(route, /conversation_members/);
  assert.doesNotMatch(route, /payload\.text|plaintext/);
  assert.match(route, /not a member of this conversation/);
  assert.doesNotMatch(route, /INSERT OR IGNORE INTO conversation_members/);
  assert.match(conversationsRoute, /WHERE cm\.user_id = \?/);
  assert.match(social, /cache-control/);
  assert.match(schema, /idx_messages_conversation_created_at/);
  assert.match(hosting, /"d1": "DB"/);
});

test("handles empty or invalid API responses without exposing JSON parser errors", async () => {
  const client = await readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8");
  assert.match(client, /async function readApiResponse/);
  assert.match(client, /The server returned an empty response/);
  assert.match(client, /The server returned an invalid response/);
  assert.match(client, /readApiResponse<\{ conversation\?/);
});

test("encrypts reaction events before persistence", async () => {
  const [client, route] = await Promise.all([
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/messages/route.ts", import.meta.url), "utf8"),
  ]);

  assert.match(client, /`\[reaction\].*targetId/);
  assert.match(client, /persistEncryptedControl/);
  assert.doesNotMatch(route, /reaction|emoji/);
});

test("keeps drafts device-local and provides in-chat search", async () => {
  const [client, route] = await Promise.all([
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/messages/route.ts", import.meta.url), "utf8"),
  ]);

  assert.match(client, /whisper-draft:/);
  assert.match(client, /chatSearchResults/);
  assert.match(client, /Search messages in/);
  assert.doesNotMatch(route, /draft/);
});

test("enforces authenticated accounts, contacts, membership, blocks, and reports", async () => {
  const [page, social, authServer, contacts, blocks, reports, conversations, messages, schema, migration, client] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/_lib/social.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/auth-server.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/contacts/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/blocks/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/reports/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/conversations/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/messages/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0001_outgoing_the_professor.sql", import.meta.url), "utf8"),
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(page, /AuthGate/);
  assert.match(authServer, /__Host-whisper_session/);
  assert.match(social, /sessionIdentity/);
  assert.doesNotMatch(social, /oai-authenticated|ChatGPT/);
  assert.doesNotMatch(social, /x-whisper-device-id/);
  assert.match(contacts, /INSERT OR IGNORE INTO contacts/);
  assert.match(contacts, /status = 'accepted'/);
  assert.match(blocks, /DELETE FROM contacts/);
  assert.match(reports, /INSERT INTO reports/);
  assert.doesNotMatch(reports, /ciphertext|SELECT.+messages/is);
  assert.match(conversations, /Every conversation member must be an accepted, unblocked contact/);
  assert.match(conversations, /memberIds/);
  assert.match(messages, /Messages are disabled because a conversation member is blocked/);
  assert.match(schema, /contactInvitations/);
  assert.match(schema, /export const blocks/);
  assert.match(schema, /export const reports/);
  assert.match(migration, /CREATE TABLE `contact_invitations`/);
  assert.match(client, /Contact invitation sent/);
  assert.match(client, /Report submitted for review/);
  assert.match(client, /Authenticated key exchange pending/);
});

test("uses authenticated RFC 9420 MLS sessions for multi-account chats", async () => {
  const [mls, keys, welcomes, events, messages, schema, migration, security, manifest] = await Promise.all([
    readFile(new URL("../app/mls-crypto.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/keys/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/mls/welcomes/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/mls/events/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/messages/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0002_safe_lilandra.sql", import.meta.url), "utf8"),
    readFile(new URL("../SECURITY.md", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(manifest, /"ts-mls": "1\.6\.2"/);
  assert.match(mls, /createGroup/);
  assert.match(mls, /joinGroup/);
  assert.match(mls, /createApplicationMessage/);
  assert.match(mls, /processPrivateMessage/);
  assert.match(mls, /verifyKeyPackage/);
  assert.match(mls, /false, \["sign"\]/);
  assert.match(mls, /zeroOutUint8Array/);
  assert.match(mls, /whisper-safety-v1/);
  assert.match(keys, /Device identity signature is invalid/);
  assert.match(keys, /key package versions cannot be rolled back/i);
  assert.match(welcomes, /key package has already been consumed/i);
  assert.match(events, /kind !== "commit"/);
  assert.match(messages, /Multi-account conversations require MLS encryption/);
  assert.match(schema, /export const devices/);
  assert.match(schema, /export const mlsWelcomes/);
  assert.match(schema, /export const mlsEvents/);
  assert.match(migration, /idx_mls_welcomes_key_package_once/);
  assert.match(security, /not formally audited/i);
  assert.doesNotMatch(security, /is formally audited/i);
});

test("implements encrypted multi-device linking, revocation, and recovery backups", async () => {
  const [cryptoClient, links, backups, keys, welcomes, schema, migration, client, security] = await Promise.all([
    readFile(new URL("../app/mls-crypto.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/devices/links/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/backups/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/keys/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/mls/welcomes/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0003_young_the_captain.sql", import.meta.url), "utf8"),
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../SECURITY.md", import.meta.url), "utf8"),
  ]);

  assert.match(cryptoClient, /name: "X25519"/);
  assert.match(cryptoClient, /whisper-device-link-v1/);
  assert.match(cryptoClient, /whisper-encrypted-backup-v1/);
  assert.match(cryptoClient, /additionalData/);
  assert.match(cryptoClient, /provisionDeviceToConversations/);
  assert.match(cryptoClient, /proposalType: "remove"/);
  assert.match(cryptoClient, /whisper-device-revoke-v1/);
  assert.match(links, /10 \* 60_000/);
  assert.match(links, /codeHash/);
  assert.doesNotMatch(links, /requesterPrivateKey|recoveryCode/);
  assert.match(backups, /encrypted_backups/);
  assert.doesNotMatch(backups, /userIdentityPrivateKey|message\.content|plaintext/);
  assert.match(keys, /identityRotationSignature/);
  assert.match(keys, /Device revocation signature is invalid/);
  assert.match(keys, /device_key_packages/);
  assert.match(welcomes, /consumed_at IS NULL/);
  assert.match(schema, /deviceLinkSessions/);
  assert.match(schema, /encryptedBackups/);
  assert.match(migration, /CREATE TABLE `device_link_sessions`/);
  assert.match(migration, /CREATE TABLE `encrypted_backups`/);
  assert.match(client, /Codes match — transfer keys/);
  assert.match(client, /Store this key offline/);
  assert.match(security, /does not clone live MLS session state/i);
});

test("round-trips the device-link X25519 and authenticated-encryption primitives", async () => {
  const [first, second] = await Promise.all([
    crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]),
    crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]),
  ]);
  const [firstPublic, secondPublic] = await Promise.all([
    crypto.subtle.exportKey("raw", first.publicKey),
    crypto.subtle.exportKey("raw", second.publicKey),
  ]);
  const [firstPeer, secondPeer] = await Promise.all([
    crypto.subtle.importKey("raw", secondPublic, { name: "X25519" }, false, []),
    crypto.subtle.importKey("raw", firstPublic, { name: "X25519" }, false, []),
  ]);
  const [firstShared, secondShared] = await Promise.all([
    crypto.subtle.deriveBits({ name: "X25519", public: firstPeer }, first.privateKey, 256),
    crypto.subtle.deriveBits({ name: "X25519", public: secondPeer }, second.privateKey, 256),
  ]);
  assert.deepEqual(new Uint8Array(firstShared), new Uint8Array(secondShared));
  const material = await crypto.subtle.importKey("raw", firstShared, "HKDF", false, ["deriveKey"]);
  const salt = crypto.getRandomValues(new Uint8Array(24));
  const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("whisper-device-link-v1") }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode("link-id");
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, new TextEncoder().encode("account-key"));
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, ciphertext);
  assert.equal(new TextDecoder().decode(plaintext), "account-key");
});

test("keeps uploaded media and thumbnails encrypted outside the browser", async () => {
  const [cryptoClient, reserve, objectRoute, mediaServer, client, schema, migration, hosting, worker] = await Promise.all([
    readFile(new URL("../app/media-crypto.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/attachments/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/attachments/[id]/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/_lib/media.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0004_omniscient_talkback.sql", import.meta.url), "utf8"),
    readFile(new URL("../.openai/hosting.json", import.meta.url), "utf8"),
    readFile(new URL("../worker/index.ts", import.meta.url), "utf8"),
  ]);

  assert.match(hosting, /"r2": "MEDIA"/);
  assert.match(cryptoClient, /AES-GCM/);
  assert.match(cryptoClient, /crypto\.getRandomValues\(new Uint8Array\(32\)\)/);
  assert.match(cryptoClient, /createEncryptedThumbnail/);
  assert.match(cryptoClient, /file contents do not match the declared file type/i);
  assert.match(reserve, /conversationMember/);
  assert.match(reserve, /thumbnailCiphertextSize/);
  assert.doesNotMatch(reserve, /filename|payload\.mime|payload\.key|thumbnailIv/);
  assert.match(objectRoute, /application\/octet-stream/);
  assert.match(objectRoute, /contentLength !== expectedSize/);
  assert.match(objectRoute, /x-whisper-encryption/);
  assert.match(mediaServer, /purgeExpiredAttachments/);
  assert.match(mediaServer, /status = 'pending' AND created_at <=/);
  assert.match(mediaServer, /"1d", "7d", "30d", "forever"/);
  assert.match(schema, /export const attachments/);
  assert.match(migration, /CREATE TABLE `attachments`/);
  assert.match(client, /\[attachment\]/);
  assert.match(client, /MediaRecorder/);
  assert.match(client, /Only ciphertext leaves this device/);
  assert.match(worker, /microphone=\(self\)/);
  assert.match(worker, /scheduled\(controller/);
  assert.match(worker, /scheduled_maintenance/);
  assert.match(worker, /env\.MEDIA\.delete/);
});

test("round-trips independent AES-GCM media ciphertext", async () => {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const original = crypto.getRandomValues(new Uint8Array(4096));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, original);
  assert.equal(ciphertext.byteLength, original.byteLength + 16);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  assert.deepEqual(new Uint8Array(plaintext), original);
});

test("implements persistent production safety and abuse operations", async () => {
  const [safety, social, health, operations, messages, attachments, contacts, reports, gifs, schema, migration, environment, runbook] = await Promise.all([
    readFile(new URL("../app/api/_lib/safety.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/_lib/social.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/health/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/operations/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/messages/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/attachments/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/contacts/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/reports/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/gifs/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0005_sad_vin_gonzales.sql", import.meta.url), "utf8"),
    readFile(new URL("../.env.example", import.meta.url), "utf8"),
    readFile(new URL("../docs/OPERATIONS.md", import.meta.url), "utf8"),
  ]);
  assert.match(safety, /ON CONFLICT\(actor_key, scope, window_start\) DO UPDATE/);
  assert.match(safety, /request_count = request_count \+ 1/);
  assert.match(safety, /enforceRestriction/);
  assert.match(safety, /ALERT_WEBHOOK_URL/);
  assert.doesNotMatch(safety, /ciphertext|filename|email/);
  assert.match(social, /CREATE TABLE IF NOT EXISTS security_events/);
  assert.match(health, /SELECT 1 AS healthy/);
  assert.match(health, /mediaBucket\(\)\.head/);
  assert.match(operations, /isOperationsAdmin/);
  assert.match(operations, /abuse_restrictions/);
  assert.doesNotMatch(operations, /FROM\s+messages|SELECT[^;]+reports[^;]+details|ciphertext/is);
  assert.match(messages, /messages-minute/);
  assert.match(attachments, /costLimit: 300/);
  assert.match(contacts, /contact-invites/);
  assert.match(reports, /reports-day/);
  assert.match(gifs, /anonymousActorKey/);
  assert.match(schema, /rateLimitBuckets/);
  assert.match(schema, /securityEvents/);
  assert.match(schema, /abuseRestrictions/);
  assert.match(migration, /CREATE TABLE `rate_limit_buckets`/);
  assert.match(environment, /OPS_ADMIN_USER_IDS/);
  assert.match(runbook, /Quarterly recovery drill/);
  assert.match(runbook, /point-in-time recovery/i);
});

test("publishes privacy and terms disclosures", async () => {
  const [privacyResponse, termsResponse] = await Promise.all([render("/privacy"), render("/terms")]);
  assert.equal(privacyResponse.status, 200);
  assert.equal(termsResponse.status, 200);
  const [privacy, terms] = await Promise.all([privacyResponse.text(), termsResponse.text()]);
  assert.match(privacy, /Privacy Policy/);
  assert.match(privacy, /What end-to-end encryption does and does not hide/);
  assert.match(privacy, /We do not sell personal information/);
  assert.match(terms, /Terms of Service/);
  assert.match(terms, /Acceptable use/);
  assert.match(terms, /has not received a formal independent security audit/);
});

test("stores reply context inside encrypted message content", async () => {
  const [client, route] = await Promise.all([
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/messages/route.ts", import.meta.url), "utf8"),
  ]);

  assert.match(client, /\[message\].*replyTo/);
  assert.match(client, /replyToId: replyingTo \? String\(replyingTo\.id\)/);
  assert.match(client, /Jump to replied message/);
  assert.match(client, /encryptMessage\(secureChat\.id, storedContent\)/);
  assert.doesNotMatch(route, /replyTo/);
});

test("syncs edits and deletions as encrypted control events", async () => {
  const [client, route] = await Promise.all([
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/messages/route.ts", import.meta.url), "utf8"),
  ]);

  assert.match(client, /`\[edit\].*targetId/);
  assert.match(client, /`\[delete\].*targetId/);
  assert.match(client, /persistEncryptedControl/);
  assert.doesNotMatch(route, /\bedit\b|\bdelete\b|targetId/);
});

test("persists device preferences and applies real conversation filters", async () => {
  const [client, styles] = await Promise.all([
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
  ]);

  assert.match(client, /whisper-chat-preferences:/);
  assert.match(client, /conversationFilter === "groups"/);
  assert.match(client, /conversationFilter === "unread"/);
  assert.match(client, /You are all caught up\./);
  assert.match(client, /chat\.kind === "saved"/);
  assert.match(client, /updateChatPreference\("pinned"\)/);
  assert.match(client, /updateChatPreference\("muted"\)/);
  assert.match(client, /updateChatPreference\("archived"\)/);
  assert.match(client, /Conversation restored/);
  assert.match(client, /persistChatPreferences\(activeChat, \{ unread \}\)/);
  assert.match(client, /Conversation marked as unread/);
  assert.match(client, /preferences\.unread/);
  assert.match(client, /navigator\.clipboard\.writeText\(message\.text\)/);
  assert.match(client, /Copy message/);
  assert.match(client, /whisper-theme/);
  assert.match(client, /theme-\$\{theme\}/);
  assert.match(client, /whisper-palette-v1/);
  assert.match(client, /palette-\$\{palette\}/);
  assert.match(client, /Black Card/);
  assert.match(client, /Night Vision/);
  assert.match(client, /Deep Cover/);
  assert.match(client, /Red Notice/);
  assert.match(client, /Cipher/);
  assert.match(styles, /\.palette-gold/);
  assert.match(styles, /\.palette-emerald/);
  assert.match(styles, /\.palette-sapphire/);
  assert.match(styles, /\.palette-crimson/);
  assert.match(styles, /\.palette-amethyst/);
  assert.match(client, /whisper-density/);
  assert.match(client, /compact-mode/);
  assert.match(client, /whisper-reduced-motion/);
  assert.match(client, /reduce-motion/);
  assert.match(client, /Keyboard shortcuts/);
  assert.match(client, /event\.key === "\/"/);
  assert.match(client, /Scroll to latest message/);
  assert.match(client, /userAwayFromBottomRef/);
  assert.match(client, /Export conversation/);
  assert.match(client, /application\/json/);
  assert.match(client, /URL\.createObjectURL/);
  assert.match(client, /aria-current=/);
  assert.match(client, /aria-pressed=/);
  assert.match(client, /aria-live="polite"/);
});

test("pins messages locally without storing decrypted message content", async () => {
  const client = await readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8");

  assert.match(client, /whisper-pinned-message:/);
  assert.match(client, /localStorage\.setItem\(storageKey, messageId\)/);
  assert.match(client, /Pinned message/);
  assert.match(client, /Unpin message/);
});

test("renders only safe web links without injecting message HTML", async () => {
  const client = await readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8");

  assert.match(client, /https\?:\\\/\\\/\[\^\\s\]\+/);
  assert.match(client, /rel="noopener noreferrer"/);
  assert.match(client, /referrerPolicy="no-referrer"/);
  assert.doesNotMatch(client, /dangerouslySetInnerHTML/);
});

test("hardens message limits, connectivity recovery, and unsupported controls", async () => {
  const [client, errorBoundary] = await Promise.all([
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/error.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(client, /MAX_MESSAGE_LENGTH = 12_000/);
  assert.match(client, /maxLength=\{MAX_MESSAGE_LENGTH\}/);
  assert.match(client, /addEventListener\("online"/);
  assert.match(client, /retrySecureSync/);
  assert.match(client, /Add encrypted attachment/);
  assert.match(client, /Encrypted calls are not available yet/);
  assert.match(errorBoundary, /reset\(\)/);
});

test("adds baseline browser security headers", async () => {
  const worker = await readFile(new URL("../worker/index.ts", import.meta.url), "utf8");
  assert.match(worker, /x-content-type-options/);
  assert.match(worker, /strict-transport-security/);
  assert.match(worker, /permissions-policy/);
  assert.match(worker, /content-security-policy/);
  assert.match(worker, /script-src 'nonce-\$\{nonce\}' 'strict-dynamic'/);
  assert.match(worker, /object-src 'none'/);
  assert.match(worker, /frame-ancestors 'none'/);
  assert.doesNotMatch(worker, /script-src[^\n]*unsafe-inline/);
});

test("keeps online GIF provider credentials on the server", async () => {
  const [route, client] = await Promise.all([
    readFile(new URL("../app/api/gifs/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(route, /TENOR_API_KEY/);
  assert.match(route, /configured: false, results: \[\]/);
  assert.doesNotMatch(route, /configured: false[\s\S]{0,120}status: 503/);
  assert.match(route, /contentfilter/);
  assert.match(route, /tenor\.googleapis\.com/);
  assert.match(client, /\/api\/gifs/);
  assert.doesNotMatch(client, /TENOR_API_KEY|tenor\.googleapis\.com/);
});

test("creates multi-contact MLS groups from the conversation picker", async () => {
  const [client, conversations] = await Promise.all([
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/conversations/route.ts", import.meta.url), "utf8"),
  ]);
  assert.match(client, /createGroupConversation/);
  assert.match(client, /Create encrypted group/);
  assert.match(client, /createMlsConversation\(currentUser, payload\.conversation\.id, groupMemberIds\)/);
  assert.match(conversations, /kind === "group"/);
  assert.match(conversations, /VALUES \(\?, \?, 'owner'\)/);
});
