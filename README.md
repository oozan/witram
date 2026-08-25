# Whisper

Whisper is a responsive Telegram-inspired chat application with client-side encryption and durable ciphertext storage.

## 0.5 milestone

The 0.5 release replaces the direct-chat placeholder with an RFC 9420 Messaging Layer Security (MLS) flow. Accounts publish signed per-device key packages, conversation creators deliver MLS Welcome messages, recipients advance through authenticated epochs, and people can compare a stable safety number out of band. Saved Messages retain the original device-local AES-GCM vault.

## What works

- ChatGPT-backed registration and sign-in without app-owned passwords
- Durable user profiles with editable display names
- Contact invitations between registered Whisper accounts
- Accept and decline workflows with symmetric contact records
- Server-enforced conversation membership limited to accepted, unblocked contacts
- Account blocking that removes contact relationships and prevents new messages
- Privacy-conscious account reporting with categories, optional details, and moderation status
- Responsive desktop and mobile conversation UI
- Device-persisted light and dark appearance themes
- Comfortable and compact chat density preferences
- A persistent reduced-motion control in addition to system motion preferences
- Visible keyboard focus, announced sync status, and semantic selected states
- Conversation search, filtering, unread states, details, and message composer
- Durable conversation creation and restoration across sessions
- Automatic encrypted message synchronization with offline status and retry controls
- A scroll-to-newest control that preserves the reader's place in long chats
- Reactions persisted as encrypted control events rather than server-readable emoji metadata
- Fast in-conversation message search with keyboard support
- Discoverable keyboard shortcut guide for search and panel navigation
- Per-conversation drafts kept locally on the device
- User-initiated local JSON conversation exports with an explicit decryption notice
- Encrypted message replies with restored quote context
- Clickable reply quotes that jump to their encrypted target message
- Safe clickable HTTP and HTTPS links without raw message HTML rendering
- Client-enforced message limits with a near-limit character counter
- Immediate offline/online detection with a manual secure-sync retry
- Recoverable application error screen and honest unavailable-feature states
- Encrypted message editing and synchronized deletion markers
- Copyable message text with clear clipboard feedback
- Device-local pinned messages with a jump-to-message banner
- Working unread/group/saved/archive filters plus device-persisted pin, mute, and archive preferences
- Device-persisted “mark as unread” reminders that clear when a chat is reopened
- Optimistic sending with delivered, read, and failed states
- RFC 9420 MLS encryption for direct-chat messages and encrypted control events
- Per-account Ed25519 identity keys and separately signed per-device identity keys
- Signed, versioned, single-use MLS key packages and server-stored opaque Welcome messages
- Forward secrecy through the MLS secret tree and user-triggered epoch rotation
- Stable safety numbers with device-local verified state
- Non-exportable Web Crypto identity private keys in IndexedDB
- AES-256-GCM encryption for Saved Messages in the browser before network transmission
- Non-exportable conversation keys stored in IndexedDB on the device
- Cloudflare D1 persistence containing ciphertext and IVs, never message plaintext
- Server-side conversation membership checks
- Payload size limits, no-store API responses, and baseline browser security headers
- ChatGPT/Sites identity headers enforced by every account and chat API
- Generated and versioned database migrations

## Run locally

Requires Node.js 22.13 or newer.

```bash
nvm install 22
nvm use
npm install
npm run dev
```

Open `http://localhost:3000`.

### Online GIF search

Whisper keeps its built-in animated GIF collection available without any external service. To also search Tenor online, copy `.env.example` to `.env.local` and add a Tenor API key as `TENOR_API_KEY`. Configure the same secret in the deployed Sites environment to enable online search there.

## Quality checks

```bash
npm run lint
npm test
```

The test command creates the production build and verifies the rendered product and encryption boundary.

## Security model

Direct-chat bodies are encrypted by `ts-mls` 1.6 using the RFC 9420 ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. The server validates account membership and signed device bundles but stores only MLS ciphertext, public commits, Welcome payloads, and routing metadata. Saved Messages continue to use AES-256-GCM with a non-exportable browser key.

This repository and its TypeScript MLS dependency have **not received a formal security audit**. It integrates a standardized protocol; that is not the same as an audited product. A second browser for an existing account is deliberately rejected until a secure account-key transfer/linking ceremony exists. Encrypted media, group membership changes, secure account recovery, push notifications, XSS hardening review, abuse operations, and an independent cryptographic assessment are still required before treating Whisper as a production replacement for Telegram or Signal. See `SECURITY.md` for the threat model and review checklist.

## Project shape

- `app/chat-app.tsx` — product interface and chat interactions
- `app/client-crypto.ts` — device-side encryption and key vault
- `app/mls-crypto.ts` — browser MLS state, key packages, epochs, and safety numbers
- `app/api/keys/route.ts` — authenticated account/device identity directory
- `app/api/mls/` — opaque MLS Welcome and public-commit transport
- `app/api/conversations/route.ts` — durable user-owned conversation API
- `app/api/messages/route.ts` — membership-protected ciphertext-only message API
- `app/api/account/route.ts` — profile registration and updates
- `app/api/contacts/route.ts` — invitations and accepted contacts
- `app/api/blocks/route.ts` — contact blocking and unblocking
- `app/api/reports/route.ts` — moderation report intake
- `db/schema.ts` — relational data model
- `drizzle/` — generated D1 migration
- `.openai/hosting.json` — deployment bindings
