import { describe, expect, it, vi, beforeEach } from "vitest";
import { mockChrome } from "../../../tests/mocks/chrome";

/**
 * Spec §17 / §19 / §22 coverage for continuous protection.
 *
 * The invariant under test is the one the spec calls out twice:
 * "One navigation/event should result in one appropriate analysis", and
 * "Do NOT trigger another scan when opening the UI."
 */

const OK_SCAN = {
  ok: true,
  data: {
    score: 30,
    riskLevel: "critical",
    verdict: "DANGEROUS",
    coverage: { url: true, domainIdentity: true, threatIntel: true, page: true, redirects: false, reputation: true },
    factors: [],
    ai: { status: "disabled" },
    scannedUrl: "https://suspicious.test/login",
    durationMs: 42,
    confidence: "high",
    analysisMode: "deterministic-only",
    safeBrowsingStatus: "NO_KNOWN_THREAT",
    evidence: [],
    aiAvailable: false,
    limitations: [],
    breakdown: [],
  },
};

let responder: (message: unknown) => unknown;
let sent: Array<{ type: string }>;

/**
 * MV3 `sendMessage` is callback-based, and the callback can silently never
 * fire if the worker was killed. The mock must therefore INVOKE the callback
 * (unlike a naive `mockResolvedValue`, which leaves the promise pending).
 */
function installSendMessage(handler: (message: unknown) => unknown): void {
  responder = handler;
  mockChrome.runtime.sendMessage = vi.fn(
    (message: unknown, cb?: (response: unknown) => void) => {
      const type = (message as { type: string }).type;
      sent.push({ type });
      if (cb) cb(responder(message));
      return undefined;
    },
  ) as never;
}

beforeEach(() => {
  sent = [];
  installSendMessage(() => OK_SCAN);
  mockChrome.tabs.query = vi.fn(async () => [
    { id: 7, url: "https://suspicious.test/login" },
  ]) as never;
  mockChrome.storage.local.get = vi.fn(async () => ({})) as never;
  mockChrome.storage.local.set = vi.fn(async () => undefined) as never;
  (globalThis as { chrome?: unknown }).chrome = mockChrome;
});

async function loadSecurityApi() {
  return import("@/services/api/securityApi");
}

describe("security API message contracts (spec §19)", () => {
  it("requests a fresh scan", async () => {
    const { scanWebsite } = await loadSecurityApi();

    await scanWebsite({ tabId: 7 });

    expect(sent).toEqual([{ type: "SCAN_WEBSITE" }]);
  });

  it("requests the last scan for a tab", async () => {
    const { getLastScan } = await loadSecurityApi();

    await getLastScan({ tabId: 7 });

    expect(sent).toEqual([{ type: "GET_LAST_SCAN" }]);
  });

  it("surfaces an error envelope when the worker gives no usable reply", async () => {
    const { scanWebsite } = await loadSecurityApi();
    // A killed service worker can reply with undefined.
    installSendMessage(() => undefined);

    const response = await scanWebsite({ tabId: 7 });

    expect(response.ok).toBe(false);
    if (!response.ok) {
      expect(response.error.code).toBe("unknown");
    }
  });

  it("surfaces an error when the extension context is invalidated", async () => {
    const { scanWebsite } = await loadSecurityApi();
    mockChrome.runtime.sendMessage = vi.fn(() => {
      throw new Error("Extension context invalidated.");
    }) as never;

    const response = await scanWebsite({ tabId: 7 });

    expect(response.ok).toBe(false);
    if (!response.ok) {
      expect(response.error.message).toMatch(/reloaded/i);
    }
  });
});

describe("scan deduplication contract (spec §19, §21 rule 9)", () => {
  it("the UI can open a warning without issuing a second SCAN_WEBSITE", async () => {
    const { getLastScan, scanWebsite } = await loadSecurityApi();
    installSendMessage((message) => {
      const type = (message as { type: string }).type;
      if (type === "GET_LAST_SCAN") return OK_SCAN;
      if (type === "SCAN_WEBSITE") throw new Error("duplicate scan must not happen");
      return { ok: false, error: { code: "unknown", message: "unexpected" } };
    });

    // Simulates the auto-opened warning panel: it must read the cached
    // verdict, which means SCAN_WEBSITE is never sent.
    const cached = await getLastScan({ tabId: 7 });

    expect(cached.ok).toBe(true);
    expect(sent.filter((m) => m.type === "SCAN_WEBSITE")).toHaveLength(0);

    // The explicit user-initiated scan path still works.
    installSendMessage(() => OK_SCAN);
    await scanWebsite({ tabId: 7 });
    expect(sent.filter((m) => m.type === "SCAN_WEBSITE")).toHaveLength(1);
  });

  it("propagates a stale_scan error so the UI can fall back", async () => {
    const { getLastScan } = await loadSecurityApi();
    installSendMessage(() => ({
      ok: false,
      error: { code: "stale_scan", message: "The page changed since the last scan." },
    }));

    const response = await getLastScan({ tabId: 7 });

    expect(response.ok).toBe(false);
    if (!response.ok) {
      expect(response.error.code).toBe("stale_scan");
    }
  });
});
