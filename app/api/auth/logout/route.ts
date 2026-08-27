import { clearSessionCookie, requireSameOrigin, revokeSession } from "../../_lib/auth";
import { database, initializeDatabase, json } from "../../_lib/social";

export async function POST(request: Request) {
  try { requireSameOrigin(request); } catch { return json({ error: "Authentication request rejected" }, { status: 403 }); }
  await initializeDatabase();
  await revokeSession(database(), request);
  return json({ signedOut: true }, { headers: { "set-cookie": clearSessionCookie() } });
}
