# Whisper production acceptance

**Status:** Execution pending on the exact deployed release.

Use at least two synthetic accounts and two separately linked browsers. Test the current stable releases of Chromium, Firefox, and Safari; include one mobile and one desktop viewport. Record exact versions, OS, commit, origin, timestamp, and sanitized evidence. Never use real conversations or production personal data.

## Required journeys

1. Register, verify email, sign in, recover a password, sign out, and revoke another browser session.
2. Invite and accept a contact; create direct and group conversations; add and remove an owner-managed group member.
3. Exchange MLS messages in both directions, compare and approve the safety number, rotate an epoch, reload both clients, and confirm ciphertext still decrypts only for current members.
4. Link a second device, transfer keys only after matching the authentication code, remove it, recover with an encrypted backup, and confirm the recovered device must be re-added to active MLS chats.
5. Send image, file, video, GIF, and voice attachments; verify encrypted thumbnails, validation failures, selected retention, expiry, and manual deletion.
6. Exercise reply, edit, delete, reaction, search, unread, mute, archive, Saved Messages, palette, light/dark theme, compact density, reduced motion, keyboard navigation, focus visibility, and responsive layout.
7. Enable generic notifications only after explicit permission, receive a background alert, verify that no sender/chat/message content appears, disable it, and confirm the browser subscription is revoked.
8. Block and report a synthetic account, verify write restrictions and rate limits, inspect metadata-only operations counts, and confirm non-operators receive a concealed response.
9. Run `smoke:production`, the authorized security probe, and a separately authorized bounded load smoke against staging. Inspect browser console, Vercel Function logs, Turso/Blob state, CSP reports, and network requests for plaintext or secrets.

Every failure needs an owner, severity, deadline, fix commit, and retest result. Do not mark browser acceptance passed until every critical/high issue is closed and the full matrix is rerun.
