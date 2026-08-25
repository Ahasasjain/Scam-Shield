import type { RiskLevel } from "@shared/index";

const BADGE_STYLES: Record<RiskLevel, string> = {
  safe: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  low: "bg-lime-100 text-lime-800 dark:bg-lime-950 dark:text-lime-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  critical: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
};

export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${BADGE_STYLES[level]}`}
    >
      {level}
    </span>
  );
}
