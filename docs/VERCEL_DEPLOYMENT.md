# Deploy Whisper on Vercel

Whisper runs as a native Next.js application on Vercel. Turso provides the SQLite-compatible database and a private Vercel Blob store holds only client-encrypted attachment bytes.

## 1. Connect storage

1. Open the `witram` project in Vercel.
2. Open **Storage**, choose **Create Database**, install the **Turso** Marketplace integration, and connect it to this project.
3. Confirm that Vercel created `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` for Production, Preview, and Development.
4. In **Storage**, create a **Blob** store, select **Private**, and connect it to the same project.
5. Confirm that `BLOB_READ_WRITE_TOKEN` is present. Vercel may also authorize Blob with project OIDC credentials at runtime.

The application creates and upgrades its SQLite tables on the first authenticated request. Use a separate Turso database and Blob store for Preview deployments if preview data must be isolated from production.

## 2. Add environment variables

In **Project Settings → Environment Variables**, add the values from `.env.example`:

- `AUTH_SECRET`: generate with `openssl rand -base64 48`.
- `AUTH_PUBLIC_ORIGIN`: `https://witram.vercel.app` until a custom domain is attached.
- `RESEND_API_KEY` and `AUTH_EMAIL_FROM`: use a current Resend key and verified sender.
- `CRON_SECRET`: generate independently with `openssl rand -base64 32`.
- `OPS_ADMIN_USER_IDS`, `ALERT_WEBHOOK_URL`, `TENOR_API_KEY`, and the three `VAPID_*` values are optional.
- Google variables may remain unset until a custom domain and Google OAuth client are ready.

Never prefix server secrets with `NEXT_PUBLIC_`. Never commit `.env.local`. Rotate any credential that has been pasted into chat, logs, screenshots, or source control.

## 3. Deploy

1. Set the Vercel Framework Preset to **Next.js**.
2. Leave Root Directory as the repository root, Build Command as `npm run build`, and Output Directory empty.
3. Select Node.js 22 in Project Settings.
4. Redeploy the latest `main` commit without reusing the previous build cache.
5. Open `https://witram.vercel.app/api/health`. A ready deployment returns `status: "ok"` with database and object-storage checks.

`vercel.json` invokes `/api/cron/maintenance` daily. Vercel attaches `Authorization: Bearer <CRON_SECRET>` automatically; direct unauthenticated calls return 401.

## 4. Verify before inviting users

1. Register a fresh email account and verify the eight-digit code.
2. Sign out and back in, then test password recovery.
3. With two accounts, test invitations, a direct MLS chat, a group, blocking, and reporting.
4. Upload, download, decrypt, and delete one image and one voice message.
5. Check `/api/health`, Vercel Function logs, the Turso database, and private Blob objects.
6. Configure an external uptime monitor and follow `docs/OPERATIONS.md` for backups, alerts, recovery drills, and release evidence.

Successful deployment is not an independent cryptographic audit. The release gate intentionally remains blocked until the external review and operational evidence described in `SECURITY.md` are complete.
