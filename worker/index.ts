/** Cloudflare Worker entry point for the vinext-starter template. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
  MEDIA: R2Bucket;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

interface ScheduledController {
  cron: string;
  scheduledTime: number;
}

type ExpiredAttachment = { id: string; object_key: string; thumbnail_object_key: string | null };

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      const imageResponse = await handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
      return withSecurityHeaders(imageResponse, request);
    }

    return withSecurityHeaders(await handler.fetch(request, env, ctx), request);
  },
  scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(runScheduledMaintenance(env, controller));
  },
};

async function runScheduledMaintenance(env: Env, controller: ScheduledController) {
  const now = new Date(controller.scheduledTime || Date.now());
  const nowIso = now.toISOString();
  const abandonedBefore = new Date(now.getTime() - 3_600_000).toISOString();
  const expired = await env.DB.prepare(
    `SELECT id, object_key, thumbnail_object_key FROM attachments
     WHERE status != 'deleted' AND (
       (expires_at IS NOT NULL AND expires_at <= ?)
       OR (status = 'pending' AND created_at <= ?)
     ) ORDER BY COALESCE(expires_at, created_at) ASC LIMIT 200`,
  ).bind(nowIso, abandonedBefore).all<ExpiredAttachment>();
  const attachments = expired.results ?? [];
  await Promise.all(attachments.flatMap((attachment) => [
    env.MEDIA.delete(attachment.object_key),
    attachment.thumbnail_object_key ? env.MEDIA.delete(attachment.thumbnail_object_key) : Promise.resolve(),
  ]));

  const statements = attachments.map((attachment) => env.DB.prepare(
    "UPDATE attachments SET status = 'deleted', deleted_at = ?, updated_at = ? WHERE id = ? AND status != 'deleted'",
  ).bind(nowIso, nowIso, attachment.id));
  statements.push(
    env.DB.prepare("DELETE FROM auth_sessions WHERE expires_at <= ?").bind(nowIso),
    env.DB.prepare("DELETE FROM auth_oauth_states WHERE expires_at <= ?").bind(nowIso),
    env.DB.prepare("DELETE FROM auth_email_challenges WHERE expires_at <= ?").bind(nowIso),
    env.DB.prepare("DELETE FROM auth_password_resets WHERE expires_at <= ?").bind(nowIso),
    env.DB.prepare("DELETE FROM device_link_sessions WHERE expires_at <= ?").bind(nowIso),
    env.DB.prepare("DELETE FROM rate_limit_buckets WHERE expires_at < ?").bind(Math.floor(now.getTime() / 1000)),
    env.DB.prepare("DELETE FROM attachments WHERE status = 'deleted' AND deleted_at <= ?").bind(new Date(now.getTime() - 30 * 86_400_000).toISOString()),
    env.DB.prepare("DELETE FROM security_events WHERE created_at <= ?").bind(new Date(now.getTime() - 180 * 86_400_000).toISOString()),
    env.DB.prepare(
      "INSERT INTO security_events (id, actor_id, category, severity, endpoint, metadata, created_at) VALUES (?, NULL, 'scheduled_maintenance', 'info', 'cron', ?, ?)",
    ).bind(crypto.randomUUID(), JSON.stringify({ expiredAttachments: attachments.length, cron: controller.cron }), nowIso),
  );
  await env.DB.batch(statements);
}

async function withSecurityHeaders(response: Response, request: Request) {
  const contentType = response.headers.get("content-type") ?? "";
  const nonceBytes = crypto.getRandomValues(new Uint8Array(18));
  const nonce = btoa(String.fromCharCode(...nonceBytes));
  const isHtml = contentType.toLowerCase().includes("text/html");
  const body = isHtml ? (await response.text()).replace(/<script(?=[\s>])/gi, `<script nonce="${nonce}"`) : response.body;
  const secured = new Response(body, response);
  if (isHtml) secured.headers.delete("content-length");
  secured.headers.set("x-content-type-options", "nosniff");
  secured.headers.set("referrer-policy", "strict-origin-when-cross-origin");
  secured.headers.set("permissions-policy", "camera=(), microphone=(self), geolocation=(), payment=()");
  secured.headers.set("cross-origin-opener-policy", "same-origin");
  secured.headers.set("cross-origin-resource-policy", "same-origin");
  secured.headers.set("content-security-policy", [
    "default-src 'self'",
    `script-src 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https://media.tenor.com https://*.tenor.com",
    "media-src 'self' blob: https://media.tenor.com https://*.tenor.com",
    "font-src 'self' data:",
    "connect-src 'self'",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; "));
  if (new URL(request.url).protocol === "https:") {
    secured.headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
  }
  return secured;
}

export default worker;
