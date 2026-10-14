import { useState } from "react";
import type { AiAnalysisResult } from "@shared/index";

interface AIAnalysisProps {
  ai:
    | { status: "enabled"; result: unknown }
    | { status: "unavailable"; reason: string }
    | { status: "disabled" };
}

function isAiResult(value: unknown): value is AiAnalysisResult {
  if (typeof value !== "object" || value === null) return false;
  const result = value as Record<string, unknown>;
  return (
    typeof result["summary"] === "string" &&
    typeof result["recommendation"] === "string" &&
    typeof result["confidence"] === "number" &&
    Number.isFinite(result["confidence"]) &&
    Array.isArray(result["indicators"])
  );
}

/**
 * AI analysis card (spec §14–§18). Renders validated AI results, the
 * graceful-unavailable message, or nothing when AI is off.
 */
export function AIAnalysis({ ai }: AIAnalysisProps) {
  const [expanded, setExpanded] = useState(true);

  if (ai.status === "disabled") return null;

  if (ai.status === "unavailable") {
    return (
      <section
        aria-label="AI analysis unavailable"
        className="rounded-2xl border border-slate-200/80 bg-white p-3.5 text-xs text-slate-500 shadow-sm dark:border-white/10 dark:bg-white/5 dark:text-slate-400"
      >
        <p className="font-semibold text-slate-800 dark:text-slate-200">
          AI analysis unavailable.
        </p>
        <p className="mt-1">{ai.reason}</p>
        <p className="mt-1">Your rule-based security scan is still available.</p>
      </section>
    );
  }

  const result = ai.result as AiAnalysisResult;

  // Defensive: the result crosses a trust boundary (AI provider → server →
  // worker → UI). A malformed payload must degrade to the unavailable card,
  // never crash the whole dashboard (there is no second chance to render).
  if (!isAiResult(result)) {
    return (
      <section
        aria-label="AI analysis unavailable"
        className="rounded-2xl border border-slate-200/80 bg-white p-3.5 text-xs text-slate-500 shadow-sm dark:border-white/10 dark:bg-white/5 dark:text-slate-400"
      >
        <p className="font-semibold text-slate-800 dark:text-slate-200">
          AI analysis unavailable.
        </p>
        <p className="mt-1">The AI service returned an unexpected response.</p>
        <p className="mt-1">Your rule-based security scan is still available.</p>
      </section>
    );
  }

  return (
    <section
      aria-label="AI analysis"
      className="rounded-2xl border border-violet-500/25 bg-gradient-to-br from-violet-500/[0.10] to-fuchsia-500/[0.05] p-3.5 shadow-sm dark:border-violet-400/20"
    >
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
        className="flex w-full items-center justify-between text-left"
      >
        <h3 className="text-sm font-semibold text-violet-900 dark:text-violet-300">
          AI Analysis
        </h3>
        <span className="flex items-center gap-2 text-xs text-violet-700 dark:text-violet-400">
          <span className="tabular-nums">
            Confidence {Math.round(result.confidence)}%
          </span>
          <span aria-hidden="true">{expanded ? "▾" : "▸"}</span>
        </span>
      </button>

      {expanded && (
        <div className="mt-2 space-y-2">
          <p className="text-xs leading-relaxed text-neutral-700 dark:text-neutral-300">
            {result.summary}
          </p>
          {result.indicators.length > 0 && (
            <ul className="space-y-1.5">
              {result.indicators.map((indicator) => (
                <li
                  key={indicator.id}
                  className="rounded-lg bg-white p-2 text-xs dark:bg-neutral-900"
                >
                  <p className="font-medium text-neutral-900 dark:text-neutral-100">
                    {indicator.title}{" "}
                    <span className="font-normal text-neutral-500 dark:text-neutral-400">
                      (−{indicator.points})
                    </span>
                  </p>
                  <p className="mt-0.5 text-neutral-600 dark:text-neutral-400">
                    {indicator.description}
                  </p>
                </li>
              ))}
            </ul>
          )}
          <p className="rounded-lg bg-white p-2 text-xs font-medium text-neutral-800 dark:bg-neutral-900 dark:text-neutral-200">
            Recommendation: {result.recommendation}
          </p>
        </div>
      )}
    </section>
  );
}
