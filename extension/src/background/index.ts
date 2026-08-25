import {
  type ExtensionMessage,
  type ExtensionResponse,
  type PageSignals,
  type RedirectSignals,
  type RiskFactor,
  type ScanRequest,
} from "@shared/index";
import { HttpAIAnalyzer } from "@/services/ai/aiAnalyzer";
import { runRuleEngine } from "@/services/scanner";
import { collectDomainSignals } from "@/services/scanner/reputationAnalyzer";
import type { ScanContext } from "@/services/scanner/ruleEngine";
import { calculateScore } from "@/utils/scoring";
import { createLogger } from "@/utils/logger";
import { isChromeInternalUrl, parseUrl } from "@/utils/url";
import { validateScanUrl } from "@/utils/validation";
import {
  addHistoryEntry,
  getAiBaseUrl,
  getSettings,
  saveSettings,
} from "@/utils/storage";

const log = createLogger("background");

interface ScanResultPayload {
  score: number;
  riskLevel: string;
  factors: RiskFactor[];
  ai:
    | { status: "enabled"; result: unknown }
    | { status: "unavailable"; reason: string }
    | { status: "disabled" };
  scannedUrl: string;
  durationMs: number;
  breakdown: { category: string; label: string; points: number }[];
}

chrome.runtime.onInstalled.addListener(() => {
  void chrome.sidePanel
    .setPanelBehavior({ openPanelOnActionClick: false })
    .catch(() => undefined);
});

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  const msg = message as ExtensionMessage;
  if (typeof msg !== "object" || msg === null || !("type" in msg)) return false;

  switch (msg.type) {
    case "SCAN_WEBSITE":
      void handleScanWebsite(msg.payload)
        .then((response) => sendResponse(response))
        .catch((error) => {
          log.error("Scan crashed", error);
          sendResponse({
            ok: false,
            error: { code: "scan_failed", message: "Unexpected scan failure." },
          } satisfies ExtensionResponse<never>);
        });
      return true; // async response

    case "GET_SETTINGS":
      void getSettings().then((settings) =>
        sendResponse({ ok: true, data: settings } satisfies ExtensionResponse<
          typeof settings
        >),
      );
      return true;

    case "UPDATE_AI_MODE":
      void saveSettings({ aiEnabled: msg.payload.enabled }).then((settings) =>
        sendResponse({ ok: true, data: settings }),
      );
      return true;

    default:
      return false;
  }
});

async function handleScanWebsite(
  payload: ScanRequest,
): Promise<ExtensionResponse<ScanResultPayload>> {
  const startedAt = Date.now();

  // 1. Detect + validate current tab URL (spec §19).
  let tabUrl: string | undefined;
  try {
    const tab = await chrome.tabs.get(payload.tabId);
    tabUrl = tab.url;
  } catch {
    return {
      ok: false,
      error: { code: "tab_not_found", message: "Could not read the active tab." },
    };
  }

  if (!tabUrl || isChromeInternalUrl(tabUrl)) {
    return {
      ok: false,
      error: {
        code: "unsupported_page",
        message:
          "ScamShield can't scan browser system pages. Open a website and try again.",
      },
    };
  }

  const validated = validateScanUrl(tabUrl);
  if (!validated.ok) {
    return {
      ok: false,
      error: { code: "invalid_url", message: validated.reason },
    };
  }

  // 2. Collect permitted metadata.
  const parsed = parseUrl(validated.url);
  if (!parsed.valid) {
    return {
      ok: false,
      error: { code: "invalid_url", message: parsed.reason },
    };
  }

  const [pageSignals, redirectSignals] = await Promise.all([
    collectPageSignals(payload.tabId),
    collectRedirectSignals(payload.tabId),
  ]);
  const domainSignals = await collectDomainSignals({ urlSignals: parsed });

  // 3. Run deterministic rule engine.
  const context: ScanContext = {
    url: validated.url,
    urlSignals: parsed,
    pageSignals: pageSignals ?? undefined,
    redirectSignals: redirectSignals ?? undefined,
    domainSignals: domainSignals ?? undefined,
  };
  const { factors: ruleFactors } = runRuleEngine(context);

  // 4. Optional AI analysis.
  const settings = await getSettings();
  let aiFactors: RiskFactor[] = [];
  let aiStatus: ScanResultPayload["ai"] = { status: "disabled" };

  if (settings.aiEnabled) {
    const baseUrl = await getAiBaseUrl();
    if (!baseUrl) {
      aiStatus = {
        status: "unavailable",
        reason: "AI backend URL is not configured in Settings.",
      };
    } else {
      const analyzer = new HttpAIAnalyzer({ baseUrl });
      const aiOutcome = await analyzer.analyze(context);
      if (aiOutcome.status === "ok") {
        aiFactors = aiOutcome.result.indicators.map((indicator) => ({
          id: `ai-${indicator.id}`,
          title: indicator.title,
          description: indicator.description,
          severity: indicator.severity,
          points: indicator.points,
          source: "ai",
        }));
        aiStatus = { status: "enabled", result: aiOutcome.result };
      } else {
        aiStatus = { status: "unavailable", reason: aiOutcome.reason };
      }
    }
  }

  // 5. Combine + score (rule findings are the floor; AI adds deductions).
  const { score, riskLevel, breakdown } = calculateScore(ruleFactors, aiFactors);

  // 6. Persist minimal history metadata.
  await addHistoryEntry({
    hostname: parsed.hostname,
    score,
    riskLevel,
    scannedAt: Date.now(),
  });

  const durationMs = Date.now() - startedAt;
  log.info("Scan complete", { hostname: parsed.hostname, score, durationMs });

  return {
    ok: true,
    data: {
      score,
      riskLevel,
      factors: [...ruleFactors, ...aiFactors],
      ai: aiStatus,
      scannedUrl: validated.url,
      durationMs,
      breakdown,
    },
  };
}

/** Injects the content script on demand and collects page signals. */
async function collectPageSignals(tabId: number): Promise<PageSignals | null> {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content.js"],
    });
    const response = await chrome.tabs.sendMessage(tabId, {
      type: "COLLECT_PAGE_SIGNALS",
    });
    if (
      typeof response === "object" &&
      response !== null &&
      (response as { ok?: boolean }).ok === true
    ) {
      return (response as { signals: PageSignals }).signals;
    }
    return null;
  } catch (error) {
    log.warn("Page signal collection failed", error);
    return null;
  }
}

/**
 * Redirect chain via webNavigation if the optional permission is granted;
 * otherwise unavailable (reported honestly, never guessed).
 */
async function collectRedirectSignals(_tabId: number): Promise<RedirectSignals | null> {
  const hasPermission = await chrome.permissions.contains({
    permissions: ["webNavigation"],
  });
  if (!hasPermission) return null;
  // Full chain tracking requires webNavigation listeners; V1 reports
  // unavailable when the optional permission isn't granted.
  return null;
}
