import { requireSameOrigin } from "../_lib/auth";
import { database, identity, initializeDatabase, json, registerIdentity } from "../_lib/social";
import { enforceWriteSafety, safetyError } from "../_lib/safety";
import { pushPublicKey, validPushSubscription } from "../_lib/web-push";

function validEndpoint(value: unknown) {
  if (typeof value !== "string" || value.length > 4_096) return null;
  try {
    const endpoint = new URL(value);
    return endpoint.protocol === "https:" && ["fcm.googleapis.com", "updates.push.services.mozilla.com", "push.services.mozilla.com", "web.push.apple.com"].includes(endpoint.hostname) ? value : null;
  } catch { return null; }
}

export async function GET(request: Request) {
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  await initializeDatabase();
  await registerIdentity(current);
  const count = await database().prepare("SELECT COUNT(*) AS total FROM push_subscriptions WHERE user_id = ?").bind(current.userId).first<{ total: number }>();
  const publicKey = pushPublicKey();
  return json({ configured: Boolean(publicKey), publicKey, enabled: Number(count?.total ?? 0) > 0 });
}

export async function POST(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Notification request rejected" }, { status: 403 }); }
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > 12_000) return json({ error: "Request body is too large" }, { status: 413 });
  let subscription: unknown;
  try { subscription = await request.json(); } catch { return json({ error: "A JSON subscription is required" }, { status: 400 }); }
  if (!validPushSubscription(subscription)) return json({ error: "A valid browser push subscription is required" }, { status: 400 });
  if (!pushPublicKey()) return json({ error: "Private notifications are not configured" }, { status: 503 });
  await initializeDatabase();
  await registerIdentity(current);
  try { await enforceWriteSafety({ userId: current.userId, scope: "push-subscriptions", restriction: "account", endpoint: "/api/push", limit: 12, windowSeconds: 3_600 }); } catch (error) { return safetyError(error); }
  const db = database();
  const existing = await db.prepare("SELECT user_id FROM push_subscriptions WHERE endpoint = ? LIMIT 1").bind(subscription.endpoint).first<{ user_id: string }>();
  if (existing && existing.user_id !== current.userId) return json({ error: "This browser subscription belongs to another account" }, { status: 409 });
  const count = await db.prepare("SELECT COUNT(*) AS total FROM push_subscriptions WHERE user_id = ?").bind(current.userId).first<{ total: number }>();
  if (!existing && Number(count?.total ?? 0) >= 10) return json({ error: "Remove an old browser notification subscription first" }, { status: 409 });
  const now = new Date().toISOString();
  await db.prepare(
    `INSERT INTO push_subscriptions (id, user_id, endpoint, p256dh, auth, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(endpoint) DO UPDATE SET p256dh = excluded.p256dh, auth = excluded.auth, updated_at = excluded.updated_at`,
  ).bind(crypto.randomUUID(), current.userId, subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth, now, now).run();
  return json({ enabled: true }, { status: existing ? 200 : 201 });
}

export async function DELETE(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Notification request rejected" }, { status: 403 }); }
  const current = await identity(request);
  if (!current) return json({ error: "Sign in to continue" }, { status: 401 });
  let payload: { endpoint?: unknown; all?: unknown };
  try { payload = await request.json() as typeof payload; } catch { return json({ error: "A JSON request body is required" }, { status: 400 }); }
  await initializeDatabase();
  await registerIdentity(current);
  if (payload.all === true) {
    await database().prepare("DELETE FROM push_subscriptions WHERE user_id = ?").bind(current.userId).run();
    return json({ enabled: false });
  }
  const endpoint = validEndpoint(payload.endpoint);
  if (!endpoint) return json({ error: "A valid subscription endpoint is required" }, { status: 400 });
  await database().prepare("DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?").bind(current.userId, endpoint).run();
  return json({ enabled: false });
}
