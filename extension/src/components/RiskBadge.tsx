import type { RiskLevel } from "@shared/index";

const BADGE_STYLES: Record<RiskLevel, string> = {
  safe: "bg-emerald-500/10 text-emerald-700 ring-emerald-500/25 dark:text-emerald-300",
  low: "bg-lime-500/10 text-lime-700 ring-lime-500/25 dark:text-lime-300",
  medium: "bg-amber-500/10 text-amber-700 ring-amber-500/25 dark:text-amber-300",
  high: "bg-orange-500/10 text-orange-700 ring-orange-500/25 dark:text-orange-300",
  critical: "bg-red-500/10 text-red-700 ring-red-500/25 dark:text-red-300",
};

export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-widest ring-1 ring-inset ${BADGE_STYLES[level]}`}
    >
      {level}
    </span>
  );
}
