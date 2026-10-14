import type { ExtensionResponse, ExtensionSettings, ScanRequest } from "@shared/index";

/**
 * Typed messaging client used by popup/sidepanel UIs to talk to the
 * background service worker (spec §28). No `any`, no untyped casts at
 * call sites.
 */

/**
 * A hung service worker must not leave the UI spinning forever. MV3 workers
 * can be killed mid-request, in which case the callback may never fire at
 * all, so every request is bounded (spec §21 rule 10: handle failures
 * gracefully).
 */
const REQUEST_TIMEOUT_MS = 30_000;

function sendMessage<T>(message: unknown): Promise<ExtensionResponse<T>> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (response: ExtensionResponse<T>): void => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timer);
      resolve(response);
    };

    const timer = globalThis.setTimeout(() => {
      finish({
        ok: false,
        error: {
          code: "timeout",
          message: "The security scan took too long. Please try again.",
        },
      });
    }, REQUEST_TIMEOUT_MS);

    try {
      chrome.runtime.sendMessage(message, (response: unknown) => {
        if (typeof response === "object" && response !== null && "ok" in response) {
          finish(response as ExtensionResponse<T>);
        } else {
          finish({
            ok: false,
            error: { code: "unknown", message: "No response from background." },
          });
        }
      });
    } catch {
      // The extension context can be invalidated (update/reload).
      finish({
        ok: false,
        error: { code: "unavailable", message: "ScamShield was reloaded." },
      });
    }
  });
}

export function scanWebsite(payload: ScanRequest): Promise<ExtensionResponse<unknown>> {
  return sendMessage({ type: "SCAN_WEBSITE", payload });
}

/**
 * Spec §17: fetch the verdict the background already computed for this tab so
 * that auto-opening the warning UI does NOT trigger a second scan.
 */
export function getLastScan(
  payload: ScanRequest,
): Promise<ExtensionResponse<unknown>> {
  return sendMessage({ type: "GET_LAST_SCAN", payload });
}

export function getSettings(): Promise<ExtensionResponse<ExtensionSettings>> {
  return sendMessage({ type: "GET_SETTINGS" });
}
