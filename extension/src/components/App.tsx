import { useCallback, useEffect, useState } from "react";
import { scoreToRiskLevel, type RiskFactor, type RiskLevel } from "@shared/index";
import { scanWebsite } from "@/services/api/securityApi";
import { getAiBaseUrl, setAiBaseUrl } from "@/utils/storage";
import { useSettings, useTheme } from "@/hooks/useExtensionState";
import { SecurityScore } from "@/components/SecurityScore";
import { RiskFactorCard } from "@/components/RiskFactors";
import { AIAnalysis } from "@/components/AIAnalysis";
import { AIModeToggle } from "@/components/AIModeToggle";
import { WebsiteInfo } from "@/components/WebsiteInfo";
import { ScanProgress } from "@/components/ScanProgress";
import { RecommendationCard } from "@/components/RecommendationCard";
import { ScanHistory } from "@/components/ScanHistory";
import { SettingsPanel } from "@/components/SettingsPanel";
import { WhyThisScore } from "@/components/WhyThisScore";
import { ErrorState, EmptyState } from "@/components/ErrorState";

type View = "dashboard" | "history" | "settings";

interface ScanResult {
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

interface ScanError {
  code: string;
  message: string;
}

const ERROR_TITLES: Record<string, string> = {
  unsupported_page: "Page can't be scanned",
  invalid_url: "Invalid address",
  tab_not_found: "Tab unavailable",
  scan_failed: "Scan failed",
};

/**
 * Shared dashboard app used by both the popup and the side panel.
 * Business logic lives in hooks/services — this is presentation + glue only.
 */
export function App({ variant }: { variant: "popup" | "sidepanel" }) {
  const { settings, update } = useSettings();
  const [view, setView] = useState<View>("dashboard");
  const [scanning, setScanning] = useState(false);
  const [progressStep, setProgressStep] = useState("Preparing");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<ScanError | null>(null);
  const [aiBaseUrl, setAiBaseUrlState] = useState("");
  const [currentUrl, setCurrentUrl] = useState<string | null>(null);

  useTheme(settings?.theme);

  useEffect(() => {
    void getAiBaseUrl().then(setAiBaseUrlState);
    void chrome.tabs
      .query({ active: true, currentWindow: true })
      .then((tabs) => setCurrentUrl(tabs[0]?.url ?? null))
      .catch(() => setCurrentUrl(null));
  }, []);

  const runScan = useCallback(async () => {
    if (scanning) return;
    setScanning(true);
    setError(null);
    setResult(null);
    setProgressStep("Validating URL");

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tabId = tabs[0]?.id;
      if (typeof tabId !== "number") {
        setError({ code: "tab_not_found", message: "No active tab found." });
        return;
      }
      setProgressStep("Collecting signals");
      const response = await scanWebsite({ tabId });
      if (!response.ok) {
        setError(response.error);
        return;
      }
      setResult(response.data as ScanResult);
    } catch {
      setError({
        code: "scan_failed",
        message: "Something went wrong while scanning. Please try again.",
      });
    } finally {
      setScanning(false);
    }
  }, [scanning]);

  const riskLevel: RiskLevel | null = result ? scoreToRiskLevel(result.score) : null;

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-md flex-col bg-neutral-50 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">
      {/* Header */}
      <header className="sticky top-0 z-10 border-b border-neutral-200 bg-white/90 px-4 py-3 backdrop-blur dark:border-neutral-800 dark:bg-neutral-900/90">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span aria-hidden="true" className="text-lg">
              🛡️
            </span>
            <h1 className="text-base font-bold tracking-tight">ScamShield</h1>
          </div>
          <nav aria-label="Sections" className="flex gap-1">
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
                className={`rounded-lg px-2.5 py-1 text-xs font-medium transition-colors ${
                  view === key
                    ? "bg-shield-600 text-white"
                    : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-800"
                }`}
              >
                {label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      <main
        className={`flex-1 space-y-3 p-3 ${variant === "sidepanel" ? "max-w-none" : ""}`}
      >
        {view === "dashboard" && (
          <>
            <AIModeToggle
              enabled={settings?.aiEnabled ?? false}
              onChange={(enabled) => update({ aiEnabled: enabled })}
            />

            <button
              type="button"
              onClick={() => void runScan()}
              disabled={scanning || !currentUrl}
              className="w-full rounded-xl bg-shield-600 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-shield-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {scanning ? "Scanning…" : "Scan this website"}
            </button>

            {scanning && <ScanProgress step={progressStep} />}

            {error && (
              <ErrorState
                title={ERROR_TITLES[error.code] ?? "Error"}
                message={error.message}
              />
            )}

            {!scanning && !error && !result && (
              <EmptyState
                icon="🔍"
                title="Ready to scan"
                message="Click “Scan this website” to analyze the current page for scam and phishing indicators."
              />
            )}

            {!scanning && result && riskLevel && (
              <div className="space-y-3">
                <section className="ss-animate-in rounded-xl border border-neutral-200 bg-white shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
                  <SecurityScore score={result.score} riskLevel={riskLevel} />
                </section>

                <RecommendationCard riskLevel={riskLevel} />

                {(riskLevel === "high" || riskLevel === "critical") && (
                  <div
                    role="alert"
                    className="ss-animate-in rounded-xl border border-red-300 bg-red-50 p-3 text-xs font-medium leading-relaxed text-red-800 dark:border-red-800 dark:bg-red-950/40 dark:text-red-300"
                  >
                    ⚠️ Avoid entering passwords, card information, OTPs, or personal
                    information on this website unless you trust it.
                  </div>
                )}

                <AIAnalysis ai={result.ai} />

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

                <details className="rounded-xl border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-900">
                  <summary className="cursor-pointer text-sm font-semibold">
                    Why this score?
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

        {view === "history" && <HistoryView onCleared={() => setView("dashboard")} />}

        {view === "settings" && settings && (
          <SettingsPanel
            settings={settings}
            aiBaseUrl={aiBaseUrl}
            onAiBaseUrlChange={(url) => {
              setAiBaseUrlState(url);
              void setAiBaseUrl(url);
            }}
            onUpdate={(patch) => update(patch)}
            onReset={() =>
              void update({ aiEnabled: false, autoScan: false, theme: "system" })
            }
          />
        )}
      </main>

      <footer className="px-4 pb-3 pt-1 text-center text-[10px] leading-relaxed text-neutral-400 dark:text-neutral-600">
        ScamShield provides probabilistic risk indicators, not guarantees.
      </footer>
    </div>
  );
}

function HistoryView({ onCleared }: { onCleared: () => void }) {
  const [history, setHistory] = useState<
    { hostname: string; score: number; riskLevel: string; scannedAt: number }[]
  >([]);

  useEffect(() => {
    void import("@/utils/storage").then(async ({ getHistory }) =>
      setHistory(await getHistory()),
    );
  }, []);

  return (
    <ScanHistory
      history={history}
      onClear={() => {
        void import("@/utils/storage").then(async ({ clearHistory }) => {
          await clearHistory();
          setHistory([]);
          onCleared();
        });
      }}
    />
  );
}
