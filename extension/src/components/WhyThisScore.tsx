import type { ScoreBreakdownEntry } from "@/utils/scoring";

interface WhyThisScoreProps {
  breakdown: ScoreBreakdownEntry[];
}

/** Trust explanation (spec §22) — shows each category's score contribution. */
export function WhyThisScore({ breakdown }: WhyThisScoreProps) {
  if (breakdown.length === 0) {
    return (
      <p className="text-xs text-neutral-500 dark:text-neutral-400">
        No deductions — no risk indicators were matched by any rule.
      </p>
    );
  }

  return (
    <ul className="space-y-1.5" aria-label="Score contribution by category">
      {breakdown.map((entry) => (
        <li key={entry.category} className="flex items-center justify-between gap-2">
          <span className="text-xs text-neutral-600 dark:text-neutral-400">
            {entry.label}
          </span>
          <span className="flex items-center gap-2">
            <span className="h-1.5 w-20 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
              <span
                className="block h-full rounded-full bg-risk-medium"
                style={{ width: `${Math.min(100, entry.points)}%` }}
              />
            </span>
            <span className="w-10 text-right text-xs font-semibold tabular-nums text-neutral-700 dark:text-neutral-300">
              −{entry.points}
            </span>
          </span>
        </li>
      ))}
    </ul>
  );
}
