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
    <ul className="space-y-2" aria-label="Score contribution by category">
      {breakdown.map((entry) => (
        <li key={entry.category} className="flex items-center justify-between gap-3">
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {entry.label}
          </span>
          <span className="flex shrink-0 items-center gap-2">
            <span className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-200 dark:bg-white/10">
              <span
                className="block h-full rounded-full bg-gradient-to-r from-amber-400 to-orange-500"
                style={{ width: `${Math.min(100, entry.points)}%` }}
              />
            </span>
            <span className="w-10 text-right text-xs font-bold tabular-nums text-slate-600 dark:text-slate-300">
              −{entry.points}
            </span>
          </span>
        </li>
      ))}
    </ul>
  );
}
