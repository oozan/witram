import { database, json } from "./social";

type Severity = "info" | "warning" | "critical";
type RestrictionScope = "all" | "messages" | "media" | "contacts" | "account";
type SafeMetadata = Record<string, string | number | boolean | null>;

export class RateLimitError extends Error {
  constructor(public retryAfter: number) {
    super("Too many requests. Please wait before trying again.");
  }
}

export class RestrictedActionError extends Error {
  constructor(public reason: string) {
    super("This action is temporarily restricted because of an account safety review.");
  }
}

function cleanMetadata(metadata: SafeMetadata) {
  return Object.fromEntries(Object.entries(metadata).slice(0, 12).map(([key, value]) => [key.slice(0, 40), typeof value === "string" ? value.slice(0, 160) : value]));
}

async function deliverAlert(payload: Record<string, unknown>) {
  const webhook = process.env.ALERT_WEBHOOK_URL?.trim();
  if (!webhook?.startsWith("https://")) return { configured: false, delivered: false };
  try {
    const response = await fetch(webhook, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5_000),
    });
    return { configured: true, delivered: response.ok };
  } catch {
    return { configured: true, delivered: false };
  }
}

export async function sendAlertTest() {
  return deliverAlert({ service: "whisper", category: "alert_delivery_test", severity: "info", test: true, occurredAt: new Date().toISOString() });
}

export async function recordSecurityEvent(input: {
  actorId?: string | null;
  category: string;
  severity: Severity;
  endpoint: string;
  metadata?: SafeMetadata;
}) {
  const metadata = cleanMetadata(input.metadata ?? {});
  await database().prepare(
    "INSERT INTO security_events (id, actor_id, category, severity, endpoint, metadata) VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), input.actorId ?? null, input.category.slice(0, 50), input.severity, input.endpoint.slice(0, 100), JSON.stringify(metadata)).run();

  if (input.severity === "critical") await deliverAlert({ service: "whisper", category: input.category, severity: input.severity, endpoint: input.endpoint, metadata, occurredAt: new Date().toISOString() });
}

export async function enforceRateLimit(input: {
  actorKey: string;
  actorId?: string | null;
  scope: string;
  endpoint: string;
  limit: number;
  windowSeconds: number;
  cost?: number;
  costLimit?: number;
}) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(nowSeconds / input.windowSeconds) * input.windowSeconds;
  const expiresAt = windowStart + input.windowSeconds * 2;
  const cost = Math.max(1, Math.ceil(input.cost ?? 1));
  const db = database();
  await db.prepare(
    `INSERT INTO rate_limit_buckets (actor_key, scope, window_start, request_count, cost, expires_at)
     VALUES (?, ?, ?, 1, ?, ?)
     ON CONFLICT(actor_key, scope, window_start) DO UPDATE SET
       request_count = request_count + 1,
       cost = cost + excluded.cost,
       expires_at = excluded.expires_at`,
  ).bind(input.actorKey.slice(0, 100), input.scope.slice(0, 60), windowStart, cost, expiresAt).run();
  const bucket = await db.prepare(
    "SELECT request_count, cost FROM rate_limit_buckets WHERE actor_key = ? AND scope = ? AND window_start = ?",
  ).bind(input.actorKey.slice(0, 100), input.scope.slice(0, 60), windowStart).first<{ request_count: number; cost: number }>();

  const blocked = !bucket || Number(bucket.request_count) > input.limit || (input.costLimit !== undefined && Number(bucket.cost) > input.costLimit);
  if (blocked) {
    const retryAfter = Math.max(1, windowStart + input.windowSeconds - nowSeconds);
    await recordSecurityEvent({
      actorId: input.actorId,
      category: "rate_limit_exceeded",
      severity: "warning",
      endpoint: input.endpoint,
      metadata: { scope: input.scope, retryAfter, requestCount: Number(bucket?.request_count ?? 0), cost: Number(bucket?.cost ?? 0) },
    });
    throw new RateLimitError(retryAfter);
  }

  if (Math.random() < 0.02) await db.prepare("DELETE FROM rate_limit_buckets WHERE expires_at < ?").bind(nowSeconds).run();
  return { remaining: Math.max(0, input.limit - Number(bucket.request_count)), resetAt: windowStart + input.windowSeconds };
}

export async function enforceRestriction(userId: string, scope: RestrictionScope) {
  const restriction = await database().prepare(
    `SELECT reason FROM abuse_restrictions
     WHERE user_id = ? AND revoked_at IS NULL AND scope IN ('all', ?)
       AND (expires_at IS NULL OR expires_at > ?)
     ORDER BY created_at DESC LIMIT 1`,
  ).bind(userId, scope, new Date().toISOString()).first<{ reason: string }>();
  if (restriction) throw new RestrictedActionError(restriction.reason);
}

export async function enforceWriteSafety(input: {
  userId: string;
  scope: string;
  restriction: RestrictionScope;
  endpoint: string;
  limit: number;
  windowSeconds: number;
  cost?: number;
  costLimit?: number;
}) {
  await enforceRestriction(input.userId, input.restriction);
  return enforceRateLimit({ ...input, actorKey: `user:${input.userId}`, actorId: input.userId });
}

export function safetyError(error: unknown) {
  if (error instanceof RateLimitError) return json({ error: error.message, retryAfter: error.retryAfter }, { status: 429, headers: { "retry-after": String(error.retryAfter) } });
  if (error instanceof RestrictedActionError) return json({ error: error.message, review: true }, { status: 403 });
  throw error;
}

export async function anonymousActorKey(request: Request) {
  const address = request.headers.get("cf-connecting-ip") ?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`whisper-rate-limit-v1:${address}`));
  return `network:${Array.from(new Uint8Array(digest).slice(0, 12), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function isOperationsAdmin(userId: string) {
  const allowed = process.env.OPS_ADMIN_USER_IDS?.split(",").map((value) => value.trim()).filter(Boolean) ?? [];
  return allowed.includes(userId);
}
