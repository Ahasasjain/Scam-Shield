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
      className={`rounded-2xl border p-3.5 shadow-sm ${
        isWarning
          ? "border-orange-500/30 bg-gradient-to-br from-orange-500/[0.10] to-transparent"
          : "border-slate-200/80 bg-white dark:border-white/10 dark:bg-white/5"
      }`}
    >
      <h3
        className={`text-[10px] font-bold uppercase tracking-widest ${
          isWarning
            ? "text-orange-600 dark:text-orange-400"
            : "text-slate-400 dark:text-slate-500"
        }`}
      >
        {isWarning ? "Recommendation" : "Summary"}
      </h3>
      <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-300">
        {RECOMMENDATIONS[riskLevel]}
      </p>
    </section>
  );
}
