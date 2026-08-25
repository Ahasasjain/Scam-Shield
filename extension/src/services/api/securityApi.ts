import type { ExtensionResponse, ExtensionSettings, ScanRequest } from "@shared/index";

/**
 * Typed messaging client used by popup/sidepanel UIs to talk to the
 * background service worker (spec §28). No `any`, no untyped casts at
 * call sites.
 */

function sendMessage<T>(message: unknown): Promise<ExtensionResponse<T>> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response: unknown) => {
      if (typeof response === "object" && response !== null && "ok" in response) {
        resolve(response as ExtensionResponse<T>);
      } else {
        resolve({
          ok: false,
          error: { code: "unknown", message: "No response from background." },
        });
      }
    });
  });
}

export function scanWebsite(payload: ScanRequest): Promise<ExtensionResponse<unknown>> {
  return sendMessage({ type: "SCAN_WEBSITE", payload });
}

export function getSettings(): Promise<ExtensionResponse<ExtensionSettings>> {
  return sendMessage({ type: "GET_SETTINGS" });
}

export function updateAiMode(
  enabled: boolean,
): Promise<ExtensionResponse<ExtensionSettings>> {
  return sendMessage({ type: "UPDATE_AI_MODE", payload: { enabled } });
}
