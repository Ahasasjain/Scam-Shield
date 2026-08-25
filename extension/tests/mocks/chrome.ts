import { vi } from "vitest";

/**
 * Hand-rolled chrome.* API mock for Vitest (jsdom has no extension APIs).
 * Individual tests override the behaviors they need.
 */

const state = new Map<string, unknown>();

export const mockChrome = {
  runtime: {
    onMessage: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
    },
    onInstalled: { addListener: vi.fn() },
    sendMessage: vi.fn((_msg: unknown, cb?: (r: unknown) => void) => {
      cb?.({ ok: false, error: { code: "unknown", message: "not mocked" } });
    }),
    getURL: vi.fn((path: string) => `chrome-extension://test/${path}`),
  },
  storage: {
    local: {
      get: vi.fn(async (keys: string | string[]) => {
        const list = Array.isArray(keys) ? keys : [keys];
        const out: Record<string, unknown> = {};
        for (const key of list) {
          if (state.has(key)) out[key] = state.get(key);
        }
        return out;
      }),
      set: vi.fn(async (items: Record<string, unknown>) => {
        for (const [key, value] of Object.entries(items)) state.set(key, value);
      }),
      clear: vi.fn(async () => state.clear()),
    },
  },
  tabs: {
    query: vi.fn(async () => [{ id: 1, url: "https://example.com", title: "Example" }]),
    get: vi.fn(async (tabId: number) => ({
      id: tabId,
      url: "https://example.com",
    })),
    sendMessage: vi.fn(),
  },
  scripting: {
    executeScript: vi.fn(async () => []),
  },
  permissions: {
    contains: vi.fn(async () => false),
    request: vi.fn(async () => true),
  },
  sidePanel: {
    setPanelBehavior: vi.fn(async () => undefined),
  },
};

export function resetChromeMock(): void {
  state.clear();
  vi.clearAllMocks();
}

if (typeof globalThis.chrome === "undefined") {
  (globalThis as { chrome: unknown }).chrome = mockChrome;
}
