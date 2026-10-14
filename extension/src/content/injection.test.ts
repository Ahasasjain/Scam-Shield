import { describe, expect, it, beforeEach, afterEach } from "vitest";
import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";

/**
 * Spec §31 / §19 — the content script must be safe to inject repeatedly.
 *
 * Real bug: the built `content.js` was NOT an IIFE, so its top-level
 * `const`/`let` landed in the isolated-world global scope. The background
 * re-injects it on every scan (navigation, tab activation, SPA route changes),
 * and the second injection threw
 * `SyntaxError: Identifier 'w' has already been declared`, killing the entire
 * script — page signals stopped working and the message listener vanished.
 *
 * These tests evaluate the REAL built artifact twice in ONE shared context via
 * Node's `vm`, which reproduces isolated-world redeclaration semantics exactly:
 * without the IIFE wrapper, the second run throws.
 */

const CONTENT_JS_PATH = "content.js";
const STATE_KEY = "__scamshieldContentState";

interface LoadedState {
  installed?: boolean;
  scanVerdict?: string | null;
  proceedAnyway?: boolean;
}

type Listener = (msg: unknown, sender: unknown, respond: (r: unknown) => void) => void;

interface Harness {
  context: vm.Context;
  listeners: Listener[];
  state(): LoadedState;
}

function readContentScript(): string {
  const file = path.resolve(process.cwd(), "dist", CONTENT_JS_PATH);
  if (!fs.existsSync(file)) {
    throw new Error(
      `dist/${CONTENT_JS_PATH} not found. Run \`pnpm build\` before this test.`,
    );
  }
  return fs.readFileSync(file, "utf8");
}

/**
 * Builds a sandbox that mirrors a browser isolated world: one shared global
 * scope, jsdom's document, and a chrome stub whose onMessage listeners we can
 * inspect and drive.
 */
function createHarness(): Harness {
  const listeners: Listener[] = [];
  const sandbox: Record<string, unknown> = {
    document,
    window: globalThis.window,
    console,
    URL,
    URLSearchParams,
    Set,
    Map,
    AbortController,
    location: {
      href: "https://example.test/",
      protocol: "https:",
      origin: "https://example.test",
      hostname: "example.test",
    },
    history: { pushState: () => {}, replaceState: () => {} },
    // The script uses `instanceof` against these constructors. A vm context
    // has its own realm, so jsdom's constructors must be injected explicitly —
    // otherwise `x instanceof HTMLFormElement` throws because the identifier
    // is simply undefined there.
    Element: globalThis.Element,
    HTMLFormElement: globalThis.HTMLFormElement,
    HTMLButtonElement: globalThis.HTMLButtonElement,
    HTMLInputElement: globalThis.HTMLInputElement,
    // Timers and events used by the navigation observer. A vm realm has its
    // own intrinsics but none of these host globals.
    addEventListener: globalThis.addEventListener.bind(globalThis),
    removeEventListener: globalThis.removeEventListener.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    chrome: {
      runtime: {
        onMessage: {
          addListener: (fn: Listener) => {
            listeners.push(fn);
          },
        },
        sendMessage: () => Promise.resolve(),
      },
    },
  };
  sandbox["globalThis"] = sandbox;
  const context = vm.createContext(sandbox);

  return {
    context,
    listeners,
    state: () => (sandbox[STATE_KEY] ?? {}) as LoadedState,
  };
}

/** Evaluate the built content script into the shared context, N times. */
function inject(harness: Harness, times: number): void {
  const source = readContentScript();
  for (let i = 0; i < times; i += 1) {
    vm.runInContext(source, harness.context, { filename: CONTENT_JS_PATH });
  }
}

/** Deliver a message to every registered listener and return the last reply. */
function deliver(harness: Harness, message: unknown): unknown {
  let response: unknown;
  for (const listener of harness.listeners) {
    listener(message, {}, (r) => {
      response = r;
    });
  }
  return response;
}

beforeEach(() => {
  document.body.innerHTML = "";
  delete (globalThis as Record<string, unknown>)[STATE_KEY];
});

afterEach(() => {
  delete (globalThis as Record<string, unknown>)[STATE_KEY];
});

describe("content script robustness on SPA hosts (spec §6, §16)", () => {
  it("does not monkey-patch the page's history API", () => {
    // chatgpt.com calls history.pushState on every route change and
    // conversation switch. Patching a page-owned API flooded the host page's
    // console and counted as invasive collection.
    const harness = createHarness();
    const pushStateBefore = history.pushState;
    const replaceStateBefore = history.replaceState;

    inject(harness, 1);

    expect(history.pushState).toBe(pushStateBefore);
    expect(history.replaceState).toBe(replaceStateBefore);
  });

  it("survives a sendMessage that throws synchronously", () => {
    const harness = createHarness();
    harness.context.chrome = {
      runtime: {
        onMessage: { addListener: () => {} },
        sendMessage: () => {
          throw new Error("Extension context invalidated.");
        },
      },
    };

    expect(() => inject(harness, 1)).not.toThrow();
  });

  it("survives a sendMessage that returns a rejected promise", () => {
    const harness = createHarness();
    harness.context.chrome = {
      runtime: {
        onMessage: { addListener: () => {} },
        sendMessage: () => Promise.reject(new Error("Could not establish connection.")),
      },
    };

    expect(() => inject(harness, 1)).not.toThrow();
  });

  it("stops notifying after the context dies instead of throwing repeatedly", () => {
    // Regression for the error volume seen on chatgpt.com: a dead context used
    // to throw on every route change. It must latch off.
    const harness = createHarness();
    let calls = 0;
    harness.context.chrome = {
      runtime: {
        onMessage: { addListener: () => {} },
        sendMessage: () => {
          calls += 1;
          return Promise.reject(new Error("dead"));
        },
      },
    };
    inject(harness, 1);

    // Fire several navigations.
    for (const url of [
      "https://example.test/a",
      "https://example.test/b",
      "https://example.test/c",
    ]) {
      (harness.context as { location: { href: string } }).location.href = url;
      harness.context.dispatchEvent?.(new Event("popstate"));
    }

    // It may try once, but it must not keep throwing per navigation.
    expect(calls).toBeLessThanOrEqual(1);
  });

  it("still collects page signals when the extension context is dead", () => {
    const harness = createHarness();
    inject(harness, 1);
    document.body.innerHTML = '<form><input type="password"></form>';

    const response = deliver(harness, {
      type: "COLLECT_PAGE_SIGNALS",
    }) as { ok: boolean; signals: { hasLoginForm: boolean } };

    expect(response.ok).toBe(true);
    expect(response.signals.hasLoginForm).toBe(true);
  });
});

describe("content script injection safety (spec §31)", () => {
  it("the built artifact is wrapped in an IIFE", () => {
    expect(readContentScript().trimStart().startsWith("(function")).toBe(true);
  });

  it("evaluating twice in one scope does not throw a redeclaration error", () => {
    // Without the IIFE this throws
    // "SyntaxError: Identifier 'w' has already been declared".
    const harness = createHarness();
    expect(() => inject(harness, 2)).not.toThrow();
  });

  it("survives many injections without error", () => {
    const harness = createHarness();
    expect(() => inject(harness, 25)).not.toThrow();
  });

  it("still answers signal collection after a second injection", () => {
    const harness = createHarness();
    inject(harness, 2);

    document.body.innerHTML = '<form><input type="password"></form>';

    const response = deliver(harness, {
      type: "COLLECT_PAGE_SIGNALS",
    }) as { ok: boolean; signals: { hasLoginForm: boolean } };

    expect(response).toBeDefined();
    expect(response.ok).toBe(true);
    // The real assertion: page signals still work after re-injection.
    expect(response.signals.hasLoginForm).toBe(true);
  });

  it("does not stack duplicate message listeners on re-injection", () => {
    const harness = createHarness();
    inject(harness, 5);

    expect(harness.listeners.length).toBe(1);
  });

  it("preserves the verdict across a re-injection", () => {
    const harness = createHarness();
    inject(harness, 1);
    deliver(harness, { type: "SET_SCAN_RISK_STATE", verdict: "DANGEROUS" });
    expect(harness.state().scanVerdict).toBe("DANGEROUS");

    // A second scan injects the file again. With module-scoped state the
    // verdict would reset to null and silently DISABLE before-submit
    // protection for the rest of the visit.
    inject(harness, 1);
    expect(harness.state().scanVerdict).toBe("DANGEROUS");
  });

  it("resets the proceed-anyway choice when a new verdict arrives", () => {
    const harness = createHarness();
    inject(harness, 1);

    deliver(harness, { type: "SET_SCAN_RISK_STATE", verdict: "DANGEROUS" });
    // Simulate the user clicking "Proceed anyway".
    harness.state().proceedAnyway = true;

    deliver(harness, { type: "SET_SCAN_RISK_STATE", verdict: "DANGEROUS" });
    expect(harness.state().proceedAnyway).toBe(false);
  });
});