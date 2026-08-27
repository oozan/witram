import { AuthGate } from "./auth-gate";
import { hasSessionCookie } from "./auth-server";

export const dynamic = "force-dynamic";

export default async function Home({ searchParams }: { searchParams: Promise<{ auth_error?: string }> }) {
  const [sessionHint, query] = await Promise.all([hasSessionCookie(), searchParams]);
  return <AuthGate hasSessionHint={sessionHint} authError={query.auth_error} />;
}
