import { RISK_LEVEL_LABELS, type RiskLevel } from "@shared/index";

const LEVEL_COLORS: Record<RiskLevel, string> = {
  safe: "text-risk-safe",
  low: "text-risk-low",
  medium: "text-risk-medium",
  high: "text-risk-high",
  critical: "text-risk-critical",
};

const STROKE_COLORS: Record<RiskLevel, string> = {
  safe: "#10b981",
  low: "#84cc16",
  medium: "#f59e0b",
  high: "#f97316",
  critical: "#ef4444",
};

interface SecurityScoreProps {
  score: number;
  riskLevel: RiskLevel;
}

/**
 * Animated circular score gauge. The label uses probabilistic language
 * (spec §43) — never "definitely safe".
 */
export function SecurityScore({ score, riskLevel }: SecurityScoreProps) {
  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);

  return (
    <div
      className="flex flex-col items-center gap-2 py-2"
      role="img"
      aria-label={`Security score ${score} out of 100 — ${RISK_LEVEL_LABELS[riskLevel]}`}
    >
      <div className="relative h-36 w-36">
        <svg viewBox="0 0 128 128" className="h-full w-full -rotate-90">
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            strokeWidth="10"
            className="stroke-neutral-200 dark:stroke-neutral-800"
          />
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            strokeWidth="10"
            strokeLinecap="round"
            stroke={STROKE_COLORS[riskLevel]}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="ss-score-ring transition-[stroke-dashoffset] duration-700 ease-out [--ss-dash-full:351.9]"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className={`text-4xl font-bold tabular-nums ${LEVEL_COLORS[riskLevel]}`}
          >
            {score}
          </span>
          <span className="text-[11px] font-medium uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
            / 100
          </span>
        </div>
      </div>
      <p className={`text-sm font-semibold ${LEVEL_COLORS[riskLevel]}`}>
        {RISK_LEVEL_LABELS[riskLevel]}
      </p>
    </div>
  );
}
