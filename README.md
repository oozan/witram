# Whisper

Whisper is a responsive Telegram-inspired chat application with client-side encryption and durable ciphertext storage.

## 0.7 milestone

The 0.7 release adds encrypted media: originals and thumbnails are protected in the browser with a fresh AES-256-GCM key before R2 upload, and that key travels only inside the existing end-to-end encrypted message. It supports images, local GIFs, video, voice/audio, files, membership-authorized retrieval, explicit deletion, and 1-day, 7-day, 30-day, or manual retention.

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
- Ten-minute, high-entropy device-link capabilities with ephemeral X25519 exchange
- A six-group authentication code that users compare before account keys transfer
- AES-GCM encrypted identity transfer with link-specific authenticated data
- Multiple one-time MLS key packages per device for adding a device to several chats
- Explicit “Sync chats” provisioning that adds a linked device as its own MLS member
- Account-signed device revocation plus MLS removal commits and epoch rotation
- Server-persisted encrypted recovery backups protected by a 256-bit offline key
- Lost-device replacement that restores account identity and encrypted cached history, then revokes old devices
- Non-exportable Web Crypto identity private keys in IndexedDB
- AES-256-GCM encryption for Saved Messages in the browser before network transmission
- Non-exportable conversation keys stored in IndexedDB on the device
- Cloudflare D1 persistence containing ciphertext and IVs, never message plaintext
- Server-side conversation membership checks
- Payload size limits, no-store API responses, and baseline browser security headers
- ChatGPT/Sites identity headers enforced by every account and chat API
- Generated and versioned database migrations
- Client-side encrypted image, local GIF, video, audio, voice-message, and file uploads
- Separately encrypted WebP thumbnails for image, GIF, and video previews
- MIME allowlists, file-signature checks, and per-media size limits before encryption
- R2 ciphertext storage with D1 ownership, membership, upload-state, and expiry metadata
- On-demand client decryption for previews, playback, and downloads
- Per-upload retention controls plus immediate encrypted-object deletion when the sender deletes a message

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

Online GIF search is a separate convenience feature: the provider receives the search request and the sent result remains a provider URL. For end-to-end encrypted storage, download a GIF and attach it through the encrypted file picker instead.

## Quality checks

```bash
npm run lint
npm test
```

The test command creates the production build and verifies the rendered product and encryption boundary.

## Security model

Direct-chat bodies are encrypted by `ts-mls` 1.6 using the RFC 9420 ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. The server validates account membership and signed device bundles but stores only MLS ciphertext, public commits, Welcome payloads, and routing metadata. Saved Messages continue to use AES-256-GCM with a non-exportable browser key.

This repository and its TypeScript MLS dependency have **not received a formal security audit**. It integrates standardized primitives; that is not the same as an audited product. Multi-device linking, removal, recovery, and encrypted media are implemented, but recovered devices intentionally do not clone active MLS session secrets: cached history returns, while a surviving member must add the replacement device back to each active chat. General group membership UI, push notifications, XSS hardening review, abuse operations, scheduled retention sweeps, and an independent cryptographic assessment are still required before treating Whisper as a production replacement for Telegram or Signal. See `SECURITY.md` for the threat model and review checklist.

## Project shape

- `app/chat-app.tsx` — product interface and chat interactions
- `app/client-crypto.ts` — device-side encryption and key vault
- `app/mls-crypto.ts` — browser MLS state, key packages, epochs, and safety numbers
- `app/media-crypto.ts` — file validation, AES-GCM media encryption, decryption, and thumbnail generation
- `app/api/keys/route.ts` — authenticated account/device identity directory
- `app/api/mls/` — opaque MLS Welcome and public-commit transport
- `app/api/devices/links/route.ts` — expiring encrypted device-link rendezvous
- `app/api/backups/route.ts` — ciphertext-only recovery backup storage
- `app/api/conversations/route.ts` — durable user-owned conversation API
- `app/api/messages/route.ts` — membership-protected ciphertext-only message API
- `app/api/attachments/` — authorized R2 ciphertext upload, retrieval, finalization, retention, and deletion
- `app/api/account/route.ts` — profile registration and updates
- `app/api/contacts/route.ts` — invitations and accepted contacts
- `app/api/blocks/route.ts` — contact blocking and unblocking
- `app/api/reports/route.ts` — moderation report intake
- `db/schema.ts` — relational data model
- `drizzle/` — generated D1 migration
- `.openai/hosting.json` — deployment bindings
