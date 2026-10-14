import type { RiskFactor } from "@shared/index";
import { RiskBadge } from "./RiskBadge";

const SEVERITY_ICON: Record<RiskFactor["severity"], string> = {
  low: "·",
  medium: "!",
  high: "!",
  critical: "!!",
};

interface RiskFactorCardProps {
  factor: RiskFactor;
}

/** Explainable finding card (spec §21) — always shows WHY it affected the score. */
export function RiskFactorCard({ factor }: RiskFactorCardProps) {
  const critical = factor.severity === "critical" || factor.severity === "high";
  return (
    <li className="rounded-2xl border border-slate-200/80 bg-white p-3.5 shadow-sm transition-colors hover:border-slate-300 dark:border-white/10 dark:bg-white/5 dark:hover:border-white/20">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-2.5">
          <span
            aria-hidden="true"
            className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg text-[13px] font-bold ${
              critical
                ? "bg-red-500/10 text-red-600 dark:text-red-400"
                : factor.severity === "medium"
                  ? "bg-amber-500/10 text-amber-600 dark:text-amber-400"
                  : "bg-slate-500/10 text-slate-500 dark:text-slate-400"
            }`}
          >
            {SEVERITY_ICON[factor.severity]}
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-slate-900 dark:text-white">
              {factor.title}
            </p>
            <p className="mt-0.5 text-xs leading-relaxed text-slate-500 dark:text-slate-400">
              {factor.description}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <span className="rounded-lg bg-slate-100 px-1.5 py-0.5 text-[11px] font-bold tabular-nums text-slate-600 dark:bg-white/10 dark:text-slate-300">
            −{factor.points}
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-500">
            {factor.source === "ai" ? "AI" : "Rule"}
          </span>
        </div>
      </div>
      <div className="mt-2.5">
        <RiskBadge level={factor.severity} />
      </div>
    </li>
  );
}
