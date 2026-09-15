import { database, initializeDatabase, json } from "../../_lib/social";
import { purgeExpiredAttachments } from "../../_lib/media";

export const dynamic = "force-dynamic";

function authorized(request: Request) {
  const secret = process.env.CRON_SECRET?.trim();
  const authorization = request.headers.get("authorization") ?? "";
  if (!secret || secret.length < 16 || !authorization.startsWith("Bearer ")) return false;
  const supplied = authorization.slice(7);
  const expected = new TextEncoder().encode(secret);
  const actual = new TextEncoder().encode(supplied);
  if (expected.length !== actual.length) return false;
  let difference = 0;
  for (let index = 0; index < expected.length; index += 1) difference |= expected[index] ^ actual[index];
  return difference === 0;
}

export async function GET(request: Request) {
  if (!authorized(request)) return json({ error: "Unauthorized" }, { status: 401 });
  await initializeDatabase();
  const now = new Date();
  const nowIso = now.toISOString();
  const expiredAttachments = await purgeExpiredAttachments(200);
  const db = database();
  await db.batch([
    db.prepare("DELETE FROM auth_sessions WHERE expires_at <= ?").bind(nowIso),
    db.prepare("DELETE FROM auth_oauth_states WHERE expires_at <= ?").bind(nowIso),
    db.prepare("DELETE FROM auth_email_challenges WHERE expires_at <= ?").bind(nowIso),
    db.prepare("DELETE FROM auth_password_resets WHERE expires_at <= ?").bind(nowIso),
    db.prepare("DELETE FROM auth_password_reset_intents WHERE expires_at <= ?").bind(nowIso),
    db.prepare("DELETE FROM device_link_sessions WHERE expires_at <= ?").bind(nowIso),
    db.prepare("DELETE FROM rate_limit_buckets WHERE expires_at < ?").bind(Math.floor(now.getTime() / 1_000)),
    db.prepare("DELETE FROM attachments WHERE status = 'deleted' AND deleted_at <= ?").bind(new Date(now.getTime() - 30 * 86_400_000).toISOString()),
    db.prepare("DELETE FROM security_events WHERE created_at <= ?").bind(new Date(now.getTime() - 180 * 86_400_000).toISOString()),
    db.prepare(
      "INSERT INTO security_events (id, actor_id, category, severity, endpoint, metadata, created_at) VALUES (?, NULL, 'scheduled_maintenance', 'info', 'cron', ?, ?)",
    ).bind(crypto.randomUUID(), JSON.stringify({ expiredAttachments, provider: "vercel-cron" }), nowIso),
  ]);
  return json({ ok: true, expiredAttachments, completedAt: new Date().toISOString() });
}
