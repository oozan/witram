import { database, initializeDatabase, json, mediaBucket } from "../_lib/social";
import { recordSecurityEvent } from "../_lib/safety";

export async function GET() {
  const startedAt = Date.now();
  try {
    await initializeDatabase();
    await database().prepare("SELECT 1 AS healthy").first();
    await mediaBucket().head("__whisper_healthcheck__");
    return json({ status: "ok", checks: { database: "ok", objectStorage: "ok" }, latencyMs: Date.now() - startedAt, timestamp: new Date().toISOString() });
  } catch {
    try { await recordSecurityEvent({ category: "health_check_failed", severity: "critical", endpoint: "/api/health" }); } catch { /* Both persistence and alerting may be unavailable during an outage. */ }
    return json({ status: "degraded", timestamp: new Date().toISOString() }, { status: 503 });
  }
}
