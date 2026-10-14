import { useCallback, useEffect, useRef, useState } from "react";
import {
  DEFAULT_SETTINGS,
  scoreToRiskLevel,
  type RiskFactor,
  type RiskLevel,
} from "@shared/index";
import { scanWebsite, getLastScan } from "@/services/api/securityApi";
import { getHistory, clearHistory } from "@/utils/storage";
import { useSettings, useTheme } from "@/hooks/useExtensionState";
import { RiskFactorCard } from "@/components/RiskFactors";
import { AIAnalysis } from "@/components/AIAnalysis";
import { WebsiteInfo } from "@/components/WebsiteInfo";
import { ScanProgress } from "@/components/ScanProgress";
import { ScanHistory } from "@/components/ScanHistory";
import { SettingsPanel } from "@/components/SettingsPanel";
import { WhyThisScore } from "@/components/WhyThisScore";
import { ErrorState, EmptyState } from "@/components/ErrorState";
import { VerdictCard } from "@/components/VerdictCard";
import { PrivacyExplainer } from "@/components/PrivacyExplainer";
import type {
  DetectionCoverage,
  ExtensionSettings,
  HistoryEntry,
  RiskVerdict,
} from "@shared/index";

type View = "dashboard" | "history" | "settings";

interface ScanResult {
  score: number;
  riskLevel: string;
  verdict?: RiskVerdict;
  coverage?: DetectionCoverage;
  factors: RiskFactor[];
  ai:
    | { status: "enabled"; result: unknown }
    | { status: "unavailable"; reason: string }
    | { status: "disabled" };
  scannedUrl: string;
  durationMs: number;
  analysisMode?: "deterministic-only" | "ai-enhanced" | "degraded";
  aiAvailable?: boolean;
  limitations: string[];
  breakdown: { category: string; label: string; points: number }[];
  cached?: boolean;
  cacheAgeMs?: number;
}

interface ScanError {
  code: string;
  message: string;
}

function siteOf(url: string | null): { hostname: string; secure: boolean } | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return { hostname: parsed.hostname, secure: parsed.protocol === "https:" };
  } catch {
    return null;
  }
}

function formatCacheAge(ageMs: number): string {
  const seconds = Math.floor(ageMs / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  return minutes === 1 ? "1 min ago" : `${minutes} min ago`;
}

function ScanChecklist({
  coverage,
  scannedUrl,
}: {
  coverage?: DetectionCoverage;
  scannedUrl: string;
}) {
  const checks = [
    ["URL and domain", coverage?.url && coverage.domainIdentity],
    ["Threat intelligence", coverage?.threatIntel],
    ["Page content and forms", coverage?.page],
    ["Redirect chain", coverage?.redirects],
    ["Domain reputation", coverage?.reputation],
  ] as const;
  const usesHttp = scannedUrl.toLowerCase().startsWith("http://");

  return (
    <section
      aria-label="Scan checklist"
      className="rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-white/5"
    >
      <h2 className="text-sm font-semibold tracking-tight">What was checked</h2>
      <ul className="mt-2 grid gap-1.5 text-xs">
        {checks.map(([label, available]) => (
          <li key={label} className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className={available ? "text-emerald-600" : "text-amber-600"}
            >
              {available ? "✓" : "!"}
            </span>
            <span>
              {label}: {available ? "checked" : "unavailable"}
            </span>
          </li>
        ))}
        <li
          className={`flex items-center gap-2 ${usesHttp ? "font-semibold text-red-700 dark:text-red-300" : "text-neutral-600 dark:text-neutral-400"}`}
        >
          <span aria-hidden="true">{usesHttp ? "!" : "✓"}</span>
          <span>
            Transport: {usesHttp ? "HTTP is not encrypted" : "HTTPS connection"}
          </span>
        </li>
      </ul>
      {!coverage?.page && (
        <p
          role="alert"
          className="mt-2 text-xs font-medium text-amber-700 dark:text-amber-300"
        >
          The webpage did not load or does not allow inspection. Page-content checks
          could not run.
        </p>
      )}
    </section>
  );
}

const ERROR_TITLES: Record<string, string> = {
  unsupported_page: "Page can't be scanned",
  invalid_url: "Invalid address",
  tab_not_found: "Tab unavailable",
  stale_scan: "Page changed",
  scan_failed: "Scan failed",
};

/**
 * Shared dashboard app used by both the popup and the side panel.
 * Business logic lives in hooks/services — this is presentation + glue only.
 */
export function App({
  variant,
  autoWarning = false,
}: {
  variant: "popup" | "sidepanel";
  /** Set when the background worker opened the panel due to a low auto-scan score. */
  autoWarning?: boolean;
}) {
  const { settings, update } = useSettings();
  const [view, setView] = useState<View>("dashboard");
  const [scanning, setScanning] = useState(false);
  const [progressStep, setProgressStep] = useState("Preparing");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<ScanError | null>(null);
  const [currentUrl, setCurrentUrl] = useState<string | null>(null);

  useTheme(settings?.theme);

  const updateSettings = useCallback(
    async (patch: Partial<ExtensionSettings>) => {
      if (patch.autoScan === true) {
        try {
          await chrome.permissions.request({ permissions: ["webNavigation"] });
        } catch {
          // Automatic URL/page scanning still works without redirect metadata.
        }
      }
      try {
        await update(patch);
      } catch {
        // A storage write failure keeps the current settings on screen rather
        // than rejecting into a void-called promise (unhandled rejection).
      }
    },
    [update],
  );

  useEffect(() => {
    void chrome.tabs
      .query({ active: true, currentWindow: true })
      .then((tabs) => setCurrentUrl(tabs[0]?.url ?? null))
      .catch(() => setCurrentUrl(null));
  }, []);

  const runScan = useCallback(
    async (force = false): Promise<ScanResult | null> => {
      if (scanning) return null;
      setScanning(true);
      setError(null);
      setResult(null);
      setProgressStep("Validating URL");

      try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId = tabs[0]?.id;
        if (typeof tabId !== "number") {
          setError({ code: "tab_not_found", message: "No active tab found." });
          return null;
        }
        setProgressStep("Collecting signals");
        const response = await scanWebsite(force ? { tabId, force: true } : { tabId });
        if (!response.ok) {
          setError(response.error);
          return null;
        }
        const data = response.data as ScanResult;
        setResult(data);
        return data;
      } catch {
        setError({
          code: "scan_failed",
          message: "Something went wrong while scanning. Please try again.",
        });
      } finally {
        setScanning(false);
      }
      return null;
    },
    [scanning],
  );

  // §17: the background worker already scanned this tab before deciding to
  // auto-open the panel. Reuse that verdict instead of scanning again — a
  // second scan would repeat the content-script injection, the RDAP and
  // threat-intel lookups, the AI call, and append a duplicate history entry.
  // We only fall back to a real scan if no recent result is available.
  const autoRan = useRef(false);
  useEffect(() => {
    if (!autoWarning || autoRan.current) return;
    autoRan.current = true;

    void (async () => {
      try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId = tabs[0]?.id;
        if (typeof tabId !== "number") {
          await runScan();
          return;
        }
        const cached = await getLastScan({ tabId });
        if (cached.ok) {
          setResult(cached.data as ScanResult);
          setError(null);
          return;
        }
      } catch {
        // Fall through to a live scan below.
      }
      await runScan();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoWarning]);

  const riskLevel: RiskLevel | null = result ? scoreToRiskLevel(result.score) : null;
  const site = siteOf(currentUrl);
  const shellHeight =
    variant === "popup"
      ? "min-h-[320px] max-h-[600px] overflow-y-auto ss-scroll"
      : "min-h-screen";

  return (
    <div
      className={`mx-auto flex w-full max-w-[480px] flex-col bg-gradient-to-b from-slate-50 to-slate-100 text-neutral-900 dark:from-slate-950 dark:to-neutral-950 dark:text-neutral-100 ${shellHeight}`}
    >
      {/* Header — two rows so the brand can never collide with the tabs.
          Solid background (no backdrop-blur: blur repaints on every scroll
          frame and made the panel feel jittery). */}
      <header className="sticky top-0 z-10 shrink-0 border-b border-slate-200/80 bg-white dark:border-white/10 dark:bg-slate-900">
        <div className="flex items-center gap-2.5 px-4 pb-1 pt-3">
          <span
            aria-hidden="true"
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-teal-600 shadow-sm shadow-emerald-600/30"
          >
            <svg
              width="19"
              height="19"
              viewBox="0 0 24 24"
              fill="none"
              aria-hidden="true"
            >
              <path
                d="M12 2.5 20 6v6c0 5-3.4 8.6-8 9.5C7.4 20.6 4 17 4 12V6l8-3.5Z"
                fill="white"
                fillOpacity="0.95"
              />
              <path
                d="m8.8 12 2.2 2.2 4.2-4.4"
                stroke="#059669"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </span>
          <span className="min-w-0 leading-tight">
            <span className="block text-[16px] font-bold tracking-tight">
              ScamShield
            </span>
            <span className="mt-1 block text-[10px] font-medium uppercase tracking-widest text-slate-400 dark:text-slate-500">
              Phishing protection
            </span>
          </span>
        </div>
        <nav
          aria-label="Sections"
          className="mx-3 mb-3 mt-2 grid grid-cols-3 gap-1 rounded-xl bg-slate-100 p-1 dark:bg-white/5"
        >
          {(
            [
              ["dashboard", "Scan"],
              ["history", "History"],
              ["settings", "Settings"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setView(key)}
              aria-current={view === key ? "page" : undefined}
              className={`w-full rounded-lg px-2 py-1.5 text-xs font-semibold transition-all duration-150 ${
                view === key
                  ? "bg-white text-slate-900 shadow-sm dark:bg-white/10 dark:text-white"
                  : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
              }`}
            >
              {label}
            </button>
          ))}
        </nav>
      </header>

      <main
        className={`ss-anchor block flex-1 space-y-3 p-4 ${variant === "sidepanel" ? "max-w-none" : ""}`}
      >
        {view === "dashboard" && (
          <>
            <section
              aria-label="Current website"
              className="rounded-2xl border border-slate-200/80 bg-white p-3.5 shadow-sm dark:border-white/10 dark:bg-white/5"
            >
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500">
                Current website
              </p>
              {site ? (
                <div className="mt-1.5 flex items-center gap-2">
                  <span
                    aria-hidden="true"
                    className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-[13px] font-bold text-slate-500 dark:bg-white/10 dark:text-slate-300"
                  >
                    {site.hostname.charAt(0).toUpperCase()}
                  </span>
                  <p className="min-w-0 flex-1 truncate text-sm font-semibold tracking-tight">
                    {site.hostname}
                  </p>
                  <span
                    className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest ring-1 ring-inset ${
                      site.secure
                        ? "bg-emerald-500/10 text-emerald-700 ring-emerald-500/25 dark:text-emerald-300"
                        : "bg-red-500/10 text-red-700 ring-red-500/25 dark:text-red-300"
                    }`}
                  >
                    {site.secure ? "HTTPS" : "HTTP"}
                  </span>
                </div>
              ) : (
                <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
                  No scannable page in the active tab.
                </p>
              )}
              <button
                type="button"
                onClick={() => void runScan()}
                disabled={scanning || !currentUrl}
                className="mt-3 inline-flex min-h-[44px] w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-b from-emerald-500 to-emerald-700 px-5 text-sm font-bold text-white shadow-md shadow-emerald-600/25 transition-all duration-150 hover:from-emerald-600 hover:to-emerald-700 hover:cursor-pointer active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-50 disabled:active:scale-100"
              >
                {scanning ? (
                  <>
                    <span
                      aria-hidden="true"
                      className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white"
                    />
                    Scanning…
                  </>
                ) : (
                  <>
                    <svg
                      width="16"
                      height="16"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      aria-hidden="true"
                    >
                      <circle cx="11" cy="11" r="7" />
                      <path d="m20 20-3.5-3.5" />
                    </svg>
                    Scan this website
                  </>
                )}
              </button>
            </section>

            {!scanning && result?.cached && (
              <div className="flex min-h-[36px] items-center justify-between gap-2 rounded-xl bg-slate-500/[0.07] px-3 py-1.5 text-xs dark:bg-white/5">
                <p className="text-slate-500 dark:text-slate-400">
                  Cached result · scanned {formatCacheAge(result.cacheAgeMs ?? 0)}
                </p>
                <button
                  type="button"
                  onClick={() => void runScan(true)}
                  className="shrink-0 rounded-lg px-2 py-1 text-xs font-bold text-emerald-700 transition-colors hover:bg-emerald-500/10 dark:text-emerald-300"
                >
                  Rescan
                </button>
              </div>
            )}

            {autoWarning &&
              riskLevel &&
              (riskLevel === "high" || riskLevel === "critical") && (
                <div
                  role="alert"
                  className="rounded-2xl border border-red-500/30 bg-gradient-to-br from-red-500/[0.12] to-transparent p-3.5 text-sm font-semibold leading-relaxed text-red-800 shadow-sm dark:text-red-200"
                >
                  Automatic scan flagged this website as {riskLevel} risk. Review the
                  findings below before entering any information.
                </div>
              )}

            {scanning && <ScanProgress step={progressStep} />}

            {error && (
              <ErrorState
                title={ERROR_TITLES[error.code] ?? "Error"}
                message={error.message}
              />
            )}

            {!scanning && !error && !result && (
              <EmptyState
                icon="◎"
                title="Ready to scan"
                message="Click “Scan this website” to analyze the current page for scam and phishing indicators."
              />
            )}

            {!scanning && result && riskLevel && (
              <div className="space-y-3">
                {result.verdict && <VerdictCard verdict={result.verdict} />}

                {result.aiAvailable && (
                  <p className="text-xs font-semibold text-violet-700 dark:text-violet-300">
                    AI-enhanced analysis
                  </p>
                )}

                {(riskLevel === "high" || riskLevel === "critical") && (
                  <div
                    role="alert"
                    className="rounded-2xl border border-red-500/25 bg-red-500/[0.07] p-3 text-xs font-medium leading-relaxed text-red-800 dark:text-red-200"
                  >
                    Avoid entering passwords, card information, OTPs, or personal
                    information on this website unless you trust it.
                  </div>
                )}

                <AIAnalysis ai={result.ai} />

                <ScanChecklist
                  coverage={result.coverage}
                  scannedUrl={result.scannedUrl}
                />

                {result.factors.length > 0 && (
                  <section>
                    <h2 className="mb-1.5 px-1 text-sm font-semibold">
                      Findings ({result.factors.length})
                    </h2>
                    <ul className="space-y-2">
                      {result.factors.map((factor) => (
                        <RiskFactorCard key={factor.id} factor={factor} />
                      ))}
                    </ul>
                  </section>
                )}

                <details className="rounded-2xl border border-slate-200/80 bg-white p-3.5 shadow-sm dark:border-white/10 dark:bg-white/5">
                  <summary className="cursor-pointer text-sm font-semibold tracking-tight">
                    Why this verdict?
                  </summary>
                  <div className="mt-2">
                    <WhyThisScore breakdown={result.breakdown} />
                  </div>
                </details>

                <WebsiteInfo
                  url={result.scannedUrl}
                  scanDurationMs={result.durationMs}
                />
              </div>
            )}
          </>
        )}

        {view === "history" && <HistoryView />}

        {view === "settings" &&
          (settings ? (
            <>
              <SettingsPanel
                settings={settings}
                onUpdate={(patch) => void updateSettings(patch)}
                onReset={() => void updateSettings({ ...DEFAULT_SETTINGS })}
              />
              {/* Spec §16: a user-facing explanation of what is analysed,
                  what leaves the device, and what is never collected. */}
              <PrivacyExplainer />
            </>
          ) : (
            <div aria-label="Loading settings" aria-busy="true" className="space-y-2">
              <div className="ss-skeleton h-[68px] rounded-2xl" />
              <div className="ss-skeleton h-[104px] rounded-2xl" />
              <div className="ss-skeleton h-[120px] rounded-2xl" />
            </div>
          ))}
      </main>

      <footer className="shrink-0 border-t border-slate-200/60 px-4 py-2.5 text-center text-[10px] leading-relaxed text-slate-400 dark:border-white/5 dark:text-slate-500">
        ScamShield provides probabilistic risk indicators, not guarantees.
      </footer>
    </div>
  );
}

function HistorySkeleton() {
  return (
    <div aria-label="Loading scan history" className="space-y-2" aria-busy="true">
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          className="rounded-2xl border border-slate-200/80 bg-white p-3 dark:border-white/10 dark:bg-white/5"
        >
          <div className="ss-skeleton h-3.5 w-2/3 rounded-md" />
          <div className="ss-skeleton mt-2 h-3 w-1/3 rounded-md" />
        </div>
      ))}
    </div>
  );
}

function HistoryView() {
  const [history, setHistory] = useState<HistoryEntry[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    void getHistory().then(
      (entries) => {
        if (!cancelled) setHistory(entries);
      },
      () => {
        // A storage read failure shows the empty state, not a stuck skeleton.
        if (!cancelled) setHistory([]);
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  // Reserve a stable minimum height so the loading skeleton, the empty
  // state, and the populated timeline don't resize the popup between frames.
  // (Kept well under the 600px shell cap.)
  return (
    <div className="min-h-[280px]">
      {history === null ? (
        <HistorySkeleton />
      ) : (
        <ScanHistory
          history={history}
          onClear={() => {
            void clearHistory().then(
              () => {
                setHistory([]);
              },
              () => {
                // Keep the visible entries if the clear failed.
              },
            );
          }}
        />
      )}
    </div>
  );
}
