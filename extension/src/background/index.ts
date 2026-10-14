import {
  type DetectionCoverage,
  type DetectionCoverageV2,
  type Evidence,
  type EvidenceConfidence,
  type ExtensionMessage,
  type ExtensionResponse,
  type PageSignals,
  type RedirectSignals,
  type RiskFactor,
  type RiskVerdict,
  type SafeBrowsingStatus,
  type ScanRequest,
} from "@shared/index";
import { HttpAIAnalyzer } from "@/services/ai/aiAnalyzer";
import { runRuleEngine } from "@/services/scanner";
import { collectDomainSignals } from "@/services/scanner/reputationAnalyzer";
import {
  BackendThreatProvider,
  CompositeThreatProvider,
  LocalFeedProvider,
  lookupThreatIntelligence,
} from "@/services/scanner/threatIntelligenceAnalyzer";
import {
  buildEvidence,
  deriveAnalysisMode,
  deriveConfidence,
  deriveLimitations,
} from "@/services/scanner/evidenceBuilder";
import {
  deriveVerdict,
  evaluateCorrelations,
} from "@/services/scanner/correlationEngine";
import { decideAiNeed } from "@/services/scanner/aiDecision";
import type { ScanContext } from "@/services/scanner/ruleEngine";
import { calculateScore } from "@/utils/scoring";
import { createLogger } from "@/utils/logger";
import { isChromeInternalUrl, parseUrl } from "@/utils/url";
import { validateScanUrl } from "@/utils/validation";
import { addHistoryEntry, getAiBaseUrl, getSettings } from "@/utils/storage";
import { classifyDomain } from "@/utils/domainIdentity";

const log = createLogger("background");

/**
 * Fire-and-forget badge updates must never reject. The tab is routinely gone
 * by the time a scan finishes (closed mid-scan, navigated away), and an
 * unhandled `chrome.action.setBadgeText` rejection surfaces as
 * "Uncaught (in promise) Error: No tab with id" in chrome://extensions.
 */
function setBadge(tabId: number, text: string, color?: string): void {
  if (color) {
    chrome.action.setBadgeBackgroundColor({ color }).catch(() => undefined);
  }
  chrome.action.setBadgeText({ tabId, text }).catch(() => undefined);
}

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
  // --- Spec §12 structured result ---
  confidence: EvidenceConfidence;
  analysisMode: "deterministic-only" | "ai-enhanced" | "degraded";
  safeBrowsingStatus: SafeBrowsingStatus;
  evidence: Evidence[];
  coverageV2: DetectionCoverageV2;
  aiAvailable: boolean;
  limitations: string[];
  breakdown: { category: string; label: string; points: number }[];
  /** Served from the background scan cache instead of a fresh analysis. */
  cached?: boolean;
  /** How old the cached verdict was when served (ms). */
  cacheAgeMs?: number;
}

chrome.runtime.onInstalled.addListener(() => {
  void chrome.sidePanel
    .setPanelBehavior({ openPanelOnActionClick: false })
    .catch(() => undefined);
});

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
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
      void getSettings()
        .then((settings) =>
          sendResponse({ ok: true, data: settings } satisfies ExtensionResponse<
            typeof settings
          >),
        )
        .catch((error) => {
          log.error("Get settings failed", error);
          sendResponse({
            ok: false,
            error: { code: "scan_failed", message: "Could not load settings." },
          } satisfies ExtensionResponse<never>);
        });
      return true;

    // §17: the UI reuses the verdict we already computed instead of
    // re-scanning. This is the difference between one analysis per navigation
    // and two (which also double-bills the AI provider and history).
    case "GET_LAST_SCAN":
      void handleGetLastScan(msg.payload)
        .then((response) => sendResponse(response))
        .catch((error) => {
          log.error("Get last scan failed", error);
          sendResponse({
            ok: false,
            error: { code: "scan_failed", message: "No recent scan is available." },
          } satisfies ExtensionResponse<never>);
        });
      return true;

    case "PAGE_NAVIGATED":
      if (typeof sender.tab?.id === "number") {
        void maybeAutoScan(sender.tab.id, msg.url);
      }
      return false;
    default:
      return false;
  }
});

async function handleScanWebsite(
  payload: ScanRequest,
  expectedUrl?: string,
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

  if (expectedUrl && tabUrl !== expectedUrl) {
    return {
      ok: false,
      error: {
        code: "stale_scan",
        message: "The page changed before scanning completed. Please scan again.",
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

  // Scan cache (spec §17, §19): the same URL with unchanged page/redirect
  // signals reuses the previous verdict instead of repeating the RDAP lookup,
  // threat-intel lookups, AI call, and history write. Page-signal collection
  // above is cheap and local, so it doubles as the freshness check — if the
  // page content changed, the hash differs and a full scan runs.
  const pageHash = hashSignals({ page: pageSignals, redirects: redirectSignals });
  if (!payload.force) {
    const hit = scanCache.get(validated.url);
    if (hit && Date.now() - hit.at < SCAN_CACHE_TTL_MS && hit.pageHash === pageHash) {
      const cacheAgeMs = Date.now() - hit.at;
      lastScanByTab.set(payload.tabId, {
        url: validated.url,
        at: Date.now(),
        payload: hit.payload,
      });
      log.info("Scan served from cache", {
        hostname: parsed.hostname,
        cacheAgeMs,
      });
      return { ok: true, data: { ...hit.payload, cached: true, cacheAgeMs } };
    }
  }

  const domainSignals = await collectDomainSignals({ urlSignals: parsed });

  // 3. Threat intelligence (spec §4–§7) — runs before rules; a confirmed
  // match overrides everything. Composite provider: backend (if configured)
  // first, then the bundled local feed — so threat intel ALWAYS runs.
  const aiBaseUrl = await getAiBaseUrl();
  const providers = aiBaseUrl
    ? [new BackendThreatProvider({ baseUrl: aiBaseUrl }), new LocalFeedProvider()]
    : [new LocalFeedProvider()];
  const threatProvider = new CompositeThreatProvider(providers);
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
  const domainIdentity = classifyDomain(
    parsed.hostname,
    new URL(validated.url).pathname,
  );
  const context: ScanContext = {
    url: validated.url,
    urlSignals: parsed,
    domainIdentity,
    pageSignals: pageSignals ?? undefined,
    redirectSignals: redirectSignals ?? undefined,
    domainSignals,
  };
  const { factors: ruleFactors } = runRuleEngine(context);

  // 5. Optional AI analysis (§40): additional evidence only — never
  // overrides a confirmed threat-intel match.
  let aiFactors: RiskFactor[] = [];
  let aiStatus: ScanResultPayload["ai"] = { status: "disabled" };

  const aiDecision = decideAiNeed(
    ruleFactors,
    threat.match,
    __SCAMSHIELD_AI_ALWAYS_RUN__,
  );

  if (aiBaseUrl && aiDecision.needed) {
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
  } else if (aiDecision.needed) {
    aiStatus = {
      status: "unavailable",
      reason: "AI service endpoint is not configured.",
    };
  }

  // 6. Combine + score with correlation rules and evidence caps.
  const baseFactors = [...threatFactors, ...ruleFactors, ...aiFactors];
  const correlationFactors = evaluateCorrelations(baseFactors, {
    domainIdentity,
    threatMatch: threat.match,
  });
  const allFactors = [...baseFactors, ...correlationFactors];
  const { score, riskLevel, breakdown } = calculateScore(
    [...ruleFactors, ...threatFactors],
    aiFactors,
    { domainIdentity },
  );

  // 7. Final verdict from evidence + coverage (§29–§30).
  const verdict = deriveVerdict({
    score,
    threatMatch: threat.match,
    domainIdentity,
    pageAnalyzed: pageSignals !== null,
    factorIds: allFactors.map((f) => f.id),
  });

  // Navigation may happen while remote threat or AI providers are running.
  // Never apply an old verdict to the newly loaded page.
  try {
    const currentTab = await chrome.tabs.get(payload.tabId);
    if (currentTab.url !== validated.url) {
      return {
        ok: false,
        error: {
          code: "stale_scan",
          message: "The page changed before scanning completed. Please scan again.",
        },
      };
    }
  } catch {
    return {
      ok: false,
      error: { code: "tab_not_found", message: "Could not read the active tab." },
    };
  }

  // Let the page-level content script know when a scan reaches a high-risk
  // or dangerous verdict, so it can stop risky form submissions before the
  // browser leaves the page. This is a page-local privacy-safe notification.
  try {
    await chrome.tabs.sendMessage(payload.tabId, {
      type: "SET_SCAN_RISK_STATE",
      verdict,
      showWarning:
        verdict === "SUSPICIOUS" || verdict === "HIGH_RISK" || verdict === "DANGEROUS",
    });
  } catch {
    // The content script may not be available on some pages; the scan outcome
    // remains authoritative and we should never fail the scan for that.
  }

  const coverage: DetectionCoverage = {
    url: true,
    domainIdentity: true,
    threatIntel: threat.match.available,
    page: pageSignals !== null,
    redirects: redirectSignals !== null,
    reputation: domainSignals.available,
  };

  // --- Spec §10/§12: structured, explainable result -----------------------
  // A confirmed threat-intel match is by definition a known-malicious listing.
  const safeBrowsingStatus: SafeBrowsingStatus = threat.match.available
    ? threat.match.matched
      ? "KNOWN_MALICIOUS"
      : threat.match.safeBrowsingStatus
    : threat.match.safeBrowsingStatus;

  const coverageV2: DetectionCoverageV2 = {
    url: true,
    domainIdentity: true,
    threatIntel: threat.match.available,
    page: pageSignals !== null,
    redirects: redirectSignals !== null,
    reputation: domainSignals.available,
    safeBrowsing: safeBrowsingStatus,
  };

  const evidence = buildEvidence({
    factors: allFactors,
    threat: threat.match,
    safeBrowsingStatus,
  });
  const confidence = deriveConfidence(evidence, coverageV2);
  const analysisMode = deriveAnalysisMode({
    aiRan: aiDecision.needed,
    aiSucceeded: aiStatus.status === "enabled",
    aiFindings: aiFactors.length,
    verdict,
  });
  const limitations = deriveLimitations(
    coverageV2,
    aiStatus.status === "enabled",
    threat.match,
  );

  const durationMs = Date.now() - startedAt;

  // 8. Persist minimal history metadata. No form values, no page text, no
  // credentials — only what the timeline needs to be useful (spec §18).
  await addHistoryEntry({
    url: validated.url,
    hostname: parsed.hostname,
    score,
    verdict,
    analysisMode,
    evidence: evidence.slice(0, 4).map((e) => e.title),
    scannedAt: Date.now(),
  });

  const result: ScanResultPayload = {
    score,
    riskLevel,
    verdict,
    coverage,
    factors: allFactors,
    ai: aiStatus,
    // Spec §12 structured result.
    confidence,
    analysisMode,
    safeBrowsingStatus,
    evidence,
    coverageV2,
    aiAvailable: aiStatus.status === "enabled",
    limitations,
    scannedUrl: validated.url,
    durationMs,
    breakdown,
  };

  // §17: make this verdict available to the UI so opening the warning panel
  // reuses it instead of triggering a second full scan (which would repeat
  // the content-script injection, RDAP and threat lookups, the AI call, and
  // append a duplicate history entry).
  lastScanByTab.set(payload.tabId, {
    url: validated.url,
    at: Date.now(),
    payload: result,
  });

  // Populate the scan cache (keyed by normalized URL + page hash). Cached
  // hits never append a duplicate history entry.
  scanCache.set(validated.url, { at: Date.now(), pageHash, payload: result });
  while (scanCache.size > SCAN_CACHE_MAX) {
    const oldest = scanCache.keys().next();
    if (oldest.done) break;
    scanCache.delete(oldest.value);
  }

  log.info("Scan complete", {
    hostname: parsed.hostname,
    score,
    verdict,
    confidence,
    analysisMode,
    durationMs,
  });

  return { ok: true, data: result };
}

/**
 * Most recent successful scan per tab, kept in memory only.
 *
 * In-memory (not chrome.storage) on purpose: it must not survive a service
 * worker restart, because a stale verdict for a page that has since changed
 * is worse than no verdict. The URL is re-checked before reuse.
 */
const lastScanByTab = new Map<
  number,
  { url: string; at: number; payload: ScanResultPayload }
>();

/** How long a completed scan may be handed to the UI. */
const LAST_SCAN_TTL_MS = 5 * 60 * 1000;

/**
 * Result cache keyed by normalized URL. The entry also stores a hash of the
 * cheap, locally-collected page/redirect signals: a repeat scan of the same
 * URL reuses the verdict ONLY when the page content is unchanged. A service
 * worker restart clears it (same reasoning as `lastScanByTab` — a stale
 * verdict for a changed page is worse than no verdict).
 */
const scanCache = new Map<
  string,
  { at: number; pageHash: string; payload: ScanResultPayload }
>();

/** Freshness window for a cached verdict. */
const SCAN_CACHE_TTL_MS = 5 * 60 * 1000;

/** Upper bound so long browsing sessions can't grow the map without limit. */
const SCAN_CACHE_MAX = 100;

/** Small FNV-1a hash over the JSON form of locally collected signals. */
function hashSignals(value: unknown): string {
  const text = JSON.stringify(value) ?? "null";
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16);
}

async function handleGetLastScan(
  payload: ScanRequest,
): Promise<ExtensionResponse<ScanResultPayload>> {
  const cached = lastScanByTab.get(payload.tabId);
  if (!cached || Date.now() - cached.at > LAST_SCAN_TTL_MS) {
    return {
      ok: false,
      error: {
        code: "scan_failed",
        message: "No recent scan is available for this tab.",
      },
    };
  }

  // Never show a verdict for a page the user has already navigated away from.
  try {
    const tab = await chrome.tabs.get(payload.tabId);
    if (tab.url !== cached.url) {
      return {
        ok: false,
        error: {
          code: "stale_scan",
          message: "The page changed since the last scan.",
        },
      };
    }
  } catch {
    return {
      ok: false,
      error: { code: "tab_not_found", message: "Could not read the active tab." },
    };
  }

  return { ok: true, data: cached.payload };
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
async function collectRedirectSignals(tabId: number): Promise<RedirectSignals | null> {
  const hasPermission = await chrome.permissions.contains({
    permissions: ["webNavigation"],
  });
  if (!hasPermission) return null;
  const state = redirectState.get(tabId);
  if (!state) return null;
  return {
    chainLength: state.chainLength,
    crossOriginHops: state.crossOriginHops,
    finalUrl: state.finalUrl,
  };
}

// ---------------------------------------------------------------------------
// Automatic scanning (user request): when enabled, scan every page load and
// open the side panel with a warning if the score falls below the threshold.
// ---------------------------------------------------------------------------

const AUTO_SCAN_DEBOUNCE_MS = 15_000;
const lastAutoScan = new Map<number, { url: string; at: number }>();
const activeAutoScans = new Set<number>();
const redirectState = new Map<
  number,
  {
    chainLength: number;
    crossOriginHops: number;
    lastOrigin: string | null;
    finalUrl: string;
  }
>();

chrome.webNavigation?.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  redirectState.set(details.tabId, {
    chainLength: 0,
    crossOriginHops: 0,
    lastOrigin: originOf(details.url),
    finalUrl: details.url,
  });
});

chrome.webNavigation?.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const previous = redirectState.get(details.tabId) ?? {
    chainLength: 0,
    crossOriginHops: 0,
    lastOrigin: null,
    finalUrl: details.url,
  };
  const nextOrigin = originOf(details.url);
  redirectState.set(details.tabId, {
    chainLength: previous.chainLength + 1,
    crossOriginHops:
      previous.crossOriginHops +
      (previous.lastOrigin && nextOrigin && previous.lastOrigin !== nextOrigin ? 1 : 0),
    lastOrigin: nextOrigin,
    finalUrl: details.url,
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  lastAutoScan.delete(tabId);
  activeAutoScans.delete(tabId);
  redirectState.delete(tabId);
  lastScanByTab.delete(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if ((changeInfo.status !== "complete" && !changeInfo.url) || !tab.url) return;
  void maybeAutoScan(tabId, tab.url);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  void chrome.tabs
    .get(tabId)
    .then((tab) => {
      if (tab.url) void maybeAutoScan(tabId, tab.url);
    })
    .catch(() => undefined);
});

chrome.runtime.onStartup.addListener(() => {
  void scanActiveTabs();
});

// A service worker can start after the current tab has already finished
// loading. Scan that tab immediately so the first landing page is covered.
void scanActiveTabs();

async function scanActiveTabs(): Promise<void> {
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    for (const tab of tabs) {
      if (typeof tab.id === "number" && tab.url) {
        void maybeAutoScan(tab.id, tab.url);
      }
    }
  } catch (error) {
    log.warn("Initial automatic scan failed", error);
  }
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

async function maybeAutoScan(tabId: number, url: string): Promise<void> {
  if (activeAutoScans.has(tabId)) return;
  activeAutoScans.add(tabId);
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

    const response = await handleScanWebsite({ tabId }, url);
    if (!response.ok) {
      setBadge(tabId, "!", "#d97706");
      return;
    }

    // Warn on any non-safe verdict from the evidence-based system.
    const { verdict } = response.data;
    if (
      verdict === "SUSPICIOUS" ||
      verdict === "HIGH_RISK" ||
      verdict === "DANGEROUS"
    ) {
      setBadge(tabId, "!", "#dc2626");
      await openSidePanelWithWarning(tabId);
    } else {
      // Clear any stale alert badge on safe results.
      setBadge(tabId, "");
    }
  } catch (error) {
    log.warn("Auto-scan failed", error);
  } finally {
    activeAutoScans.delete(tabId);
  }
}

async function openSidePanelWithWarning(tabId: number): Promise<void> {
  try {
    // §17: open with the warning flag so the UI renders the existing verdict
    // instead of rescanning. The panel option is PER-TAB and sticky, so it is
    // reset to the plain path as soon as the panel has been opened —
    // otherwise every later manual open on this tab would re-enter the
    // warning flow.
    await chrome.sidePanel.setOptions({
      tabId,
      path: "sidepanel.html?warning=1",
      enabled: true,
    });
    await chrome.sidePanel.open({ tabId });
    await chrome.sidePanel.setOptions({ tabId, path: "sidepanel.html", enabled: true });
  } catch (error) {
    // sidePanel.open requires a user gesture in some Chrome versions —
    // fall back to the badge as the attention signal.
    log.warn("Side panel auto-open failed", error);
    setBadge(tabId, "!", "#ef4444");
  }
}
