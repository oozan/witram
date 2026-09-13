import { initializeDatabase } from "../_lib/social";
import { anonymousActorKey, enforceRateLimit, safetyError } from "../_lib/safety";

type TenorMedia = {
  url?: string;
  dims?: [number, number];
};

type TenorResult = {
  id?: string;
  title?: string;
  content_description?: string;
  media_formats?: {
    gif?: TenorMedia;
    mediumgif?: TenorMedia;
    tinygif?: TenorMedia;
    nanogif?: TenorMedia;
  };
};

type TenorResponse = { results?: TenorResult[]; next?: string };

export async function GET(request: Request) {
  await initializeDatabase();
  try {
    const actorKey = await anonymousActorKey(request);
    await enforceRateLimit({ actorKey, scope: "gif-search-minute", endpoint: "/api/gifs", limit: 30, windowSeconds: 60 });
    await enforceRateLimit({ actorKey, scope: "gif-search-day", endpoint: "/api/gifs", limit: 400, windowSeconds: 86_400 });
  } catch (error) { return safetyError(error); }
  const tenorKey = process.env.TENOR_API_KEY;
  if (!tenorKey) {
    // The bundled encrypted emotes remain available without an online
    // provider, so an absent optional key is a valid capability state.
    return Response.json({ configured: false, results: [] });
  }

  const requestUrl = new URL(request.url);
  const query = requestUrl.searchParams.get("q")?.trim().slice(0, 80) ?? "";
  const endpoint = query ? "search" : "featured";
  const tenorUrl = new URL(`https://tenor.googleapis.com/v2/${endpoint}`);
  tenorUrl.searchParams.set("key", tenorKey);
  tenorUrl.searchParams.set("client_key", "whisper_encrypted_chat");
  tenorUrl.searchParams.set("limit", "18");
  tenorUrl.searchParams.set("contentfilter", "medium");
  tenorUrl.searchParams.set("media_filter", "gif,mediumgif,tinygif,nanogif");
  tenorUrl.searchParams.set("locale", requestUrl.searchParams.get("locale")?.slice(0, 10) || "en_US");
  if (query) tenorUrl.searchParams.set("q", query);

  try {
    const response = await fetch(tenorUrl, { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`Tenor returned ${response.status}`);
    const payload = await response.json() as TenorResponse;
    const results = (payload.results ?? []).flatMap((item) => {
      const full = item.media_formats?.mediumgif ?? item.media_formats?.gif;
      const preview = item.media_formats?.tinygif ?? item.media_formats?.nanogif ?? full;
      if (!item.id || !full?.url || !preview?.url) return [];
      return [{
        id: item.id,
        label: item.content_description || item.title || "Tenor GIF",
        url: full.url,
        previewUrl: preview.url,
        width: full.dims?.[0] ?? 320,
        height: full.dims?.[1] ?? 240,
        provider: "Tenor",
      }];
    });
    return Response.json({ configured: true, results, next: payload.next ?? null });
  } catch {
    return Response.json(
      { configured: true, results: [], error: "Online GIF search is temporarily unavailable" },
      { status: 502 },
    );
  }
}
