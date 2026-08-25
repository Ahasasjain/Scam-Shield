import type { RiskFactor } from "@shared/index";
import { RiskBadge } from "./RiskBadge";

const SEVERITY_ICON: Record<RiskFactor["severity"], string> = {
  low: "•",
  medium: "⚠",
  high: "⚠",
  critical: "⛔",
};

interface RiskFactorCardProps {
  factor: RiskFactor;
}

/** Explainable finding card (spec §21) — always shows WHY it affected the score. */
export function RiskFactorCard({ factor }: RiskFactorCardProps) {
  return (
    <li className="ss-animate-in rounded-xl border border-neutral-200 bg-white p-3 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2">
          <span
            aria-hidden="true"
            className={
              factor.severity === "critical" || factor.severity === "high"
                ? "text-risk-high"
                : "text-risk-medium"
            }
          >
            {SEVERITY_ICON[factor.severity]}
          </span>
          <div>
            <p className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
              {factor.title}
            </p>
            <p className="mt-0.5 text-xs leading-relaxed text-neutral-600 dark:text-neutral-400">
              {factor.description}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <span className="rounded-md bg-neutral-100 px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">
            −{factor.points}
          </span>
          <span className="text-[10px] uppercase tracking-wide text-neutral-400 dark:text-neutral-500">
            {factor.source === "ai" ? "AI" : "Rule"}
          </span>
        </div>
      </div>
      <div className="mt-2">
        <RiskBadge level={factor.severity} />
      </div>
    </li>
  );
}
