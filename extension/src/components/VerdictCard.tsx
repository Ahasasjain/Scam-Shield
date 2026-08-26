import {
  VERDICT_LABELS,
  VERDICT_RECOMMENDATIONS,
  type RiskVerdict,
} from "@shared/index";

const VERDICT_STYLES: Record<
  RiskVerdict,
  { box: string; icon: string; title: string }
> = {
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

interface VerdictCardProps {
  verdict: RiskVerdict;
}

/**
 * Verdict-first display (spec §31): leads with the verdict and
 * recommendation. No numeric score, no coverage noise — just whether the
 * site is reliable or not.
 */
export function VerdictCard({ verdict }: VerdictCardProps) {
  const style = VERDICT_STYLES[verdict];

  return (
    <section
      role="status"
      aria-label={`Verdict: ${VERDICT_LABELS[verdict]}`}
      className={`ss-animate-in rounded-xl border p-4 ${style.box}`}
    >
      <div className="flex items-start gap-3">
        <span aria-hidden="true" className="text-2xl leading-none">
          {style.icon}
        </span>
        <div className="min-w-0">
          <h2 className={`text-base font-bold ${style.title}`}>
            {VERDICT_LABELS[verdict]}
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-neutral-700 dark:text-neutral-300">
            {VERDICT_RECOMMENDATIONS[verdict]}
          </p>
        </div>
      </div>
    </section>
  );
}
