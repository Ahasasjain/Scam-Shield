import type { RiskLevel } from "@shared/index";

interface RecommendationCardProps {
  riskLevel: RiskLevel;
}

const RECOMMENDATIONS: Record<RiskLevel, string> = {
  safe: "No significant risk indicators detected. As always, stay alert for unusual requests.",
  low: "Few or minor indicators found. Proceed normally but remain observant.",
  medium:
    "Some indicators detected. Be cautious — verify the site before entering any information.",
  high: "Do not enter passwords, payment information, or personal information on this website unless you fully trust it.",
  critical:
    "Multiple strong indicators suggest this website may be unsafe. Do not enter passwords, card details, OTPs, or personal information.",
};

/** User warning (spec §23) — probabilistic language only (spec §43). */
export function RecommendationCard({ riskLevel }: RecommendationCardProps) {
  const isWarning = riskLevel === "high" || riskLevel === "critical";
  return (
    <section
      aria-label="Recommendation"
      className={`ss-animate-in rounded-xl border p-3 ${
        isWarning
          ? "border-orange-300 bg-orange-50 dark:border-orange-800 dark:bg-orange-950/40"
          : "border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900"
      }`}
    >
      <h3
        className={`text-xs font-semibold uppercase tracking-wide ${
          isWarning
            ? "text-orange-700 dark:text-orange-400"
            : "text-neutral-500 dark:text-neutral-400"
        }`}
      >
        {isWarning ? "Recommendation" : "Summary"}
      </h3>
      <p className="mt-1 text-xs leading-relaxed text-neutral-700 dark:text-neutral-300">
        {RECOMMENDATIONS[riskLevel]}
      </p>
    </section>
  );
}
