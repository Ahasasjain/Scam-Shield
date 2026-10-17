import { afterEach, describe, expect, it, vi } from "vitest";
import { refreshFeed } from "./openPhishFeed.js";

/**
 * The tracked server/.env.example ships `THREAT_FEED_URL=` (empty), so an empty
 * value must mean "use the default OpenPhish feed" — `??` would otherwise pass
 * "" to fetch() and leave the feed permanently unloaded in every deployment
 * that copied the example file.
 */
describe("refreshFeed feed URL resolution", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env["THREAT_FEED_URL"];
  });

  function stubFetch(): ReturnType<typeof vi.fn> {
    // No parameters: the server tsconfig has no DOM lib, so RequestInfo is not
    // in scope. A zero-arg async fn is assignable to typeof fetch for stubbing.
    const fetchMock = vi.fn(
      async () => new Response("https://phishing.example/login\n", { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("uses the default feed when THREAT_FEED_URL is empty", async () => {
    process.env["THREAT_FEED_URL"] = "";
    const fetchMock = stubFetch();

    await refreshFeed();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://openphish.com/feed.txt");
  });

  it("uses THREAT_FEED_URL when one is configured", async () => {
    process.env["THREAT_FEED_URL"] = "https://feeds.example/list.txt";
    const fetchMock = stubFetch();

    await refreshFeed();

    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://feeds.example/list.txt");
  });
});
