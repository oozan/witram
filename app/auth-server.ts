import { cookies } from "next/headers";

export async function hasSessionCookie() {
  const incoming = await cookies();
  return Boolean(incoming.get("__Host-whisper_session")?.value);
}
