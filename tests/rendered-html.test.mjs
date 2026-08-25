import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
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
  assert.match(html, /Sign in with ChatGPT/);
  assert.match(html, /never asks for or stores your password/);
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
  const [page, social, contacts, blocks, reports, conversations, messages, schema, migration, client] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/_lib/social.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/contacts/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/blocks/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/reports/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/conversations/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/messages/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0001_outgoing_the_professor.sql", import.meta.url), "utf8"),
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(page, /getChatGPTUser/);
  assert.match(page, /chatGPTSignInPath/);
  assert.match(social, /oai-authenticated-user-id/);
  assert.match(social, /oai-authenticated-user-email/);
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
  const client = await readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8");

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
  assert.match(client, /Encrypted attachments are not available yet/);
  assert.match(client, /Encrypted calls are not available yet/);
  assert.match(errorBoundary, /reset\(\)/);
});

test("adds baseline browser security headers", async () => {
  const worker = await readFile(new URL("../worker/index.ts", import.meta.url), "utf8");
  assert.match(worker, /x-content-type-options/);
  assert.match(worker, /strict-transport-security/);
  assert.match(worker, /permissions-policy/);
});

test("keeps online GIF provider credentials on the server", async () => {
  const [route, client] = await Promise.all([
    readFile(new URL("../app/api/gifs/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/chat-app.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(route, /TENOR_API_KEY/);
  assert.match(route, /contentfilter/);
  assert.match(route, /tenor\.googleapis\.com/);
  assert.match(client, /\/api\/gifs/);
  assert.doesNotMatch(client, /TENOR_API_KEY|tenor\.googleapis\.com/);
});
