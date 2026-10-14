import {
  VERDICT_LABELS,
  VERDICT_RECOMMENDATIONS,
  type RiskVerdict,
} from "@shared/index";

const VERDICT_STYLES: Record<
  RiskVerdict,
  { card: string; tile: string; eyebrow: string; title: string; icon: string }
> = {
  DANGEROUS: {
    card: "border-red-500/30 bg-gradient-to-br from-red-500/[0.12] to-red-600/[0.04] dark:border-red-500/30",
    tile: "bg-gradient-to-br from-red-500 to-red-700 text-white shadow-red-600/30",
    eyebrow: "text-red-600 dark:text-red-400",
    title: "text-red-950 dark:text-red-100",
    icon: "M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z",
  },
  HIGH_RISK: {
    card: "border-orange-500/30 bg-gradient-to-br from-orange-500/[0.12] to-orange-600/[0.04] dark:border-orange-500/30",
    tile: "bg-gradient-to-br from-orange-500 to-orange-700 text-white shadow-orange-600/30",
    eyebrow: "text-orange-600 dark:text-orange-400",
    title: "text-orange-950 dark:text-orange-100",
    icon: "M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z",
  },
  SUSPICIOUS: {
    card: "border-amber-500/30 bg-gradient-to-br from-amber-500/[0.12] to-amber-600/[0.04] dark:border-amber-500/30",
    tile: "bg-gradient-to-br from-amber-400 to-amber-600 text-white shadow-amber-600/30",
    eyebrow: "text-amber-600 dark:text-amber-400",
    title: "text-amber-950 dark:text-amber-100",
    icon: "M12 8v5m0 3.5h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
  },
  LOW_RISK: {
    card: "border-emerald-500/25 bg-gradient-to-br from-emerald-500/[0.10] to-teal-600/[0.04] dark:border-emerald-500/25",
    tile: "bg-gradient-to-br from-emerald-500 to-teal-600 text-white shadow-emerald-600/30",
    eyebrow: "text-emerald-600 dark:text-emerald-400",
    title: "text-emerald-950 dark:text-emerald-100",
    icon: "M20 6 9 17l-5-5",
  },
  SAFE: {
    card: "border-emerald-500/25 bg-gradient-to-br from-emerald-500/[0.12] to-teal-600/[0.05] dark:border-emerald-500/25",
    tile: "bg-gradient-to-br from-emerald-500 to-teal-600 text-white shadow-emerald-600/30",
    eyebrow: "text-emerald-600 dark:text-emerald-400",
    title: "text-emerald-950 dark:text-emerald-100",
    icon: "M12 2.5 20 6v6c0 5-3.4 8.6-8 9.5C7.4 20.6 4 17 4 12V6l8-3.5Z",
  },
  UNKNOWN: {
    card: "border-slate-300/60 bg-white dark:border-white/10 dark:bg-white/5",
    tile: "bg-slate-500/15 text-slate-500 dark:text-slate-300",
    eyebrow: "text-slate-500 dark:text-slate-400",
    title: "text-slate-900 dark:text-white",
    icon: "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM9.1 9a3 3 0 0 1 5.8 1c0 2-3 2.6-3 4m.1 3.5h.01",
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
      className={`ss-animate-in rounded-2xl border bg-white p-4 shadow-sm dark:bg-white/5 ${style.card}`}
    >
      <div className="flex items-start gap-3">
        <span
          aria-hidden="true"
          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl shadow-md ${style.tile}`}
        >
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d={style.icon} />
          </svg>
        </span>
        <div className="min-w-0">
          <p
            className={`text-[10px] font-bold uppercase tracking-widest ${style.eyebrow}`}
          >
            Verdict
          </p>
          <h2
            className={`mt-0.5 text-[17px] font-bold tracking-tight ${style.title}`}
          >
            {VERDICT_LABELS[verdict]}
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-300">
            {VERDICT_RECOMMENDATIONS[verdict]}
          </p>
        </div>
      </div>
    </section>
  );
}
