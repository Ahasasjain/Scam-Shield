import {
  VERDICT_LABELS,
  VERDICT_RECOMMENDATIONS,
  type DetectionCoverage,
  type RiskVerdict,
} from "@shared/index";

const VERDICT_STYLES: Record<RiskVerdict, { box: string; icon: string; title: string }> = {
  dangerous: {
    box: "border-red-500 bg-red-100 dark:bg-red-950 dark:border-red-600",
    icon: "🛑",
    title: "text-red-900 dark:text-red-200",
  },
  high_risk: {
    box: "border-orange-400 bg-orange-50 dark:bg-orange-950/60 dark:border-orange-700",
    icon: "⛔",
    title: "text-orange-900 dark:text-orange-200",
  },
  suspicious: {
    box: "border-amber-300 bg-amber-50 dark:bg-amber-950/60 dark:border-amber-700",
    icon: "⚠️",
    title: "text-amber-900 dark:text-amber-200",
  },
  low_risk: {
    box: "border-emerald-200 bg-emerald-50 dark:bg-emerald-950/40 dark:border-emerald-800",
    icon: "✅",
    title: "text-emerald-900 dark:text-emerald-200",
  },
  known_safe: {
    box: "border-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 dark:border-emerald-700",
    icon: "🛡️",
    title: "text-emerald-900 dark:text-emerald-200",
  },
  unknown: {
    box: "border-neutral-300 bg-neutral-50 dark:bg-neutral-900 dark:border-neutral-700",
    icon: "❓",
    title: "text-neutral-800 dark:text-neutral-200",
  },
};

const COVERAGE_LABELS: Record<keyof DetectionCoverage, string> = {
  url: "URL analysis",
  domainIdentity: "Domain analysis",
  threatIntel: "Threat intelligence",
  page: "Page analysis",
  redirects: "Redirect analysis",
  reputation: "Reputation data",
};

interface VerdictCardProps {
  verdict: RiskVerdict;
  coverage?: DetectionCoverage;
}

/**
 * Verdict-first display (spec §31): leads with the verdict and reasons,
 * never a bare number. Unknown coverage is shown honestly.
 */
export function VerdictCard({ verdict, coverage }: VerdictCardProps) {
  const style = VERDICT_STYLES[verdict];

  return (
    <section
      role="status"
      aria-label={`Verdict: ${VERDICT_LABELS[verdict]}`}
      className={`ss-animate-in rounded-xl border p-3 ${style.box}`}
    >
      <div className="flex items-start gap-2">
        <span aria-hidden="true" className="text-xl leading-none">
          {style.icon}
        </span>
        <div className="min-w-0">
          <h2 className={`text-sm font-bold ${style.title}`}>
            {VERDICT_LABELS[verdict]}
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-neutral-700 dark:text-neutral-300">
            {VERDICT_RECOMMENDATIONS[verdict]}
          </p>
        </div>
      </div>

      {coverage && (
        <details className="mt-2">
          <summary className="cursor-pointer text-[11px] font-medium text-neutral-600 dark:text-neutral-400">
            Coverage
          </summary>
          <ul className="mt-1 space-y-0.5">
            {(Object.keys(COVERAGE_LABELS) as Array<keyof DetectionCoverage>).map(
              (key) => (
                <li
                  key={key}
                  className="flex items-center gap-1.5 text-[11px] text-neutral-600 dark:text-neutral-400"
                >
                  <span aria-hidden="true">{coverage[key] ? "✓" : "⚠"}</span>
                  {COVERAGE_LABELS[key]}
                  {!coverage[key] && " unavailable"}
                </li>
              ),
            )}
          </ul>
        </details>
      )}
    </section>
  );
}
