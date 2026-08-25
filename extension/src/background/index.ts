import {
  type DetectionCoverage,
  type ExtensionMessage,
  type ExtensionResponse,
  type PageSignals,
  type RedirectSignals,
  type RiskFactor,
  type RiskVerdict,
  type ScanRequest,
} from "@shared/index";
import { HttpAIAnalyzer } from "@/services/ai/aiAnalyzer";
import { runRuleEngine } from "@/services/scanner";
import { collectDomainSignals } from "@/services/scanner/reputationAnalyzer";
import {
  BackendThreatProvider,
  lookupThreatIntelligence,
} from "@/services/scanner/threatIntelligenceAnalyzer";
import { deriveVerdict } from "@/services/scanner/correlationEngine";
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
import { classifyDomain } from "@/utils/domainIdentity";

const log = createLogger("background");

interface ScanResultPayload {
  score: number;
  riskLevel: string;
  verdict: RiskVerdict;
  coverage: DetectionCoverage;
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

  // 3. Threat intelligence (spec §4–§7) — runs before rules; a confirmed
  // match overrides everything. Failure never becomes "safe" (§3).
  const settings = await getSettings();
  const aiBaseUrl = await getAiBaseUrl();
  const threatProvider = aiBaseUrl
    ? new BackendThreatProvider({ baseUrl: aiBaseUrl })
    : null;
  const threat = await lookupThreatIntelligence(
    { normalizedUrl: validated.url, registrableDomain: parsed.registrableDomain },
    threatProvider,
  );
  const threatFactors: RiskFactor[] = threat.match.available
    ? threat.match.matched
      ? [
          {
            id: "threat-intel-match",
            title: "Known phishing/threat URL",
            description: `Threat intelligence (${threat.match.source ?? "provider"}) reports this URL as ${threat.match.threatType ?? "malicious"}.`,
            severity: "critical",
            points: 100,
            source: "rule",
          },
        ]
      : []
    : [];

  // 4. Run deterministic rule engine.
  const domainIdentity = classifyDomain(parsed.hostname);
  const context: ScanContext = {
    url: validated.url,
    urlSignals: parsed,
    domainIdentity,
    pageSignals: pageSignals ?? undefined,
    redirectSignals: redirectSignals ?? undefined,
    domainSignals: domainSignals ?? undefined,
  };
  const { factors: ruleFactors } = runRuleEngine(context);

  // 5. Optional AI analysis (§40): additional evidence only — never
  // overrides a confirmed threat-intel match.
  let aiFactors: RiskFactor[] = [];
  let aiStatus: ScanResultPayload["ai"] = { status: "disabled" };

  if (settings.aiEnabled && aiBaseUrl) {
    const analyzer = new HttpAIAnalyzer({ baseUrl: aiBaseUrl });
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

  // 6. Combine + score with correlation rules and evidence caps.
  const { score, riskLevel, breakdown } = calculateScore(
    [...ruleFactors, ...threatFactors],
    aiFactors,
    { domainIdentity },
  );

  // 7. Final verdict from evidence + coverage (§29–§30).
  const allFactors = [...threatFactors, ...ruleFactors, ...aiFactors];
  const verdict = deriveVerdict({
    score,
    threatMatch: threat.match,
    domainIdentity,
    pageAnalyzed: pageSignals !== null,
    factorIds: allFactors.map((f) => f.id),
  });
  const coverage: DetectionCoverage = {
    url: true,
    domainIdentity: true,
    threatIntel: threat.match.available,
    page: pageSignals !== null,
    redirects: redirectSignals !== null,
    reputation: domainSignals.available,
  };

  // 8. Persist minimal history metadata.
  await addHistoryEntry({
    hostname: parsed.hostname,
    score,
    riskLevel: verdict,
    scannedAt: Date.now(),
  });

  const durationMs = Date.now() - startedAt;
  log.info("Scan complete", {
    hostname: parsed.hostname,
    score,
    verdict,
    durationMs,
  });

  return {
    ok: true,
    data: {
      score,
      riskLevel,
      verdict,
      coverage,
      factors: allFactors,
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

// ---------------------------------------------------------------------------
// Automatic scanning (user request): when enabled, scan every page load and
// open the side panel with a warning if the score falls below the threshold.
// ---------------------------------------------------------------------------

const AUTO_SCAN_THRESHOLD = 50; // below this = medium risk or worse
const AUTO_SCAN_DEBOUNCE_MS = 15_000;
const lastAutoScan = new Map<number, { url: string; at: number }>();

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;
  void maybeAutoScan(tabId, tab.url);
});

async function maybeAutoScan(tabId: number, url: string): Promise<void> {
  try {
    const settings = await getSettings();
    if (!settings.autoScan) return;

    // Skip browser-internal and non-http(s) pages.
    if (isChromeInternalUrl(url) || !/^https?:\/\//i.test(url)) return;

    // Debounce repeated scans of the same URL in a short window.
    const now = Date.now();
    const previous = lastAutoScan.get(tabId);
    if (
      previous &&
      previous.url === url &&
      now - previous.at < AUTO_SCAN_DEBOUNCE_MS * 10
    ) {
      return;
    }
    lastAutoScan.set(tabId, { url, at: now });

    const response = await handleScanWebsite({ tabId });
    if (!response.ok) return;

    if (response.data.score < AUTO_SCAN_THRESHOLD) {
      await openSidePanelWithWarning(tabId);
    }
  } catch (error) {
    log.warn("Auto-scan failed", error);
  }
}

async function openSidePanelWithWarning(tabId: number): Promise<void> {
  try {
    await chrome.sidePanel.setOptions({
      tabId,
      path: "sidepanel.html?warning=1",
      enabled: true,
    });
    await chrome.sidePanel.open({ tabId });
  } catch (error) {
    // sidePanel.open requires a user gesture in some Chrome versions —
    // fall back to the badge as the attention signal.
    log.warn("Side panel auto-open failed", error);
    void chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    void chrome.action.setBadgeText({ tabId, text: "!" });
  }
}
