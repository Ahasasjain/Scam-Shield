import OpenAI from "openai";
import {
  aiAnalysisResultSchema,
  type AiAnalysisResult,
  type ScanContext,
} from "@scamshield/shared";
import { ApiError } from "../middleware/errorHandler.js";

/**
 * Provider-agnostic AI analyzer.
 *
 * ScamShield is now decoupled from any single AI vendor. Almost every modern
 * chat model exposes the OpenAI Chat Completions HTTP API (OpenAI, Azure
 * OpenAI, Groq, Together, Mistral, OpenRouter, Fireworks, Ollama via
 * /v1/chat/completions, etc.), so we use the official `openai` SDK with
 * a configurable base URL. JSON-mode response_format is only sent when the
 * provider actually supports it (auto-fallback for providers that don't).
 *
 * Selection is via env (see `aiProviders.ts`):
 *   AI_PROVIDER=openrouter|openai|custom   # default: openrouter
 *   AI_API_KEY=...                         # the provider's key
 *   AI_BASE_URL=...                        # overrides preset / required for custom
 *   AI_MODEL=...                           # overrides preset default
 */

const SYSTEM_PROMPT = `You are a website security analyst for ScamShield, a browser extension that detects scam and phishing websites.

You receive MINIMAL security metadata about a webpage (URL structure signals, aggregate page-content signal counts, redirect info). You never see page contents, credentials, or personal data.

Analyze the signals and respond with ONLY a JSON object matching this exact schema:
{
  "riskLevel": "safe" | "low" | "medium" | "high" | "critical",
  "confidence": number (0-100),
  "summary": string (max 2 sentences, probabilistic language — never claim a site is definitely safe or definitely a scam),
  "indicators": [{ "id": string, "title": string, "description": string, "severity": "low"|"medium"|"high"|"critical", "points": number (0-40) }],
  "recommendation": string (one actionable sentence)
}

Rules:
- Base findings ONLY on the provided signals. Do not invent facts.
- Use probabilistic language ("indicators suggest"), never absolute claims.
- If signals are benign, say so honestly — do not manufacture indicators.
- Keep at most 8 indicators.`;

/**
 * Providers that DO NOT reliably accept `response_format: { type: "json_object" }`.
 * The SDK still works; we just skip the strict JSON-mode hint for them.
 * OpenRouter routes to heterogeneous backends, so we don't rely on json mode.
 */
const PROVIDERS_WITHOUT_JSON_MODE = new Set([
  "openrouter",
  "custom",
]);

export interface AiAnalyzerConfig {
  provider: string;
  apiKey: string;
  baseUrl?: string;
  model: string;
  timeoutMs?: number;
}

/**
 * Provider-agnostic analyzer. Use any OpenAI Chat Completions–compatible
 * service by setting the env: AI_PROVIDER, AI_API_KEY, optionally
 * AI_BASE_URL, AI_MODEL.
 */
export class AiAnalyzer {
  private readonly client: OpenAI;
  private readonly model: string;
  private readonly provider: string;
  private readonly timeoutMs: number;

  constructor(config: AiAnalyzerConfig) {
    if (!config.apiKey) {
      throw new Error("AI_API_KEY is required for the configured AI provider");
    }
    const options: ConstructorParameters<typeof OpenAI>[0] = {
      apiKey: config.apiKey,
      timeout: config.timeoutMs ?? 20_000,
      maxRetries: 1,
    };
    if (config.baseUrl) options.baseURL = config.baseUrl;
    // OpenRouter best practice: attribute app traffic via these headers.
    // Harmless no-ops for every other provider.
    options.defaultHeaders = {
      "HTTP-Referer": "https://github.com/Ahasasjain/Scam-Shield",
      "X-Title": "ScamShield",
    };
    this.client = new OpenAI(options);
    this.model = config.model;
    this.provider = config.provider;
    this.timeoutMs = config.timeoutMs ?? 20_000;
  }

  async analyze(context: ScanContext): Promise<AiAnalysisResult> {
    const useJsonMode = !PROVIDERS_WITHOUT_JSON_MODE.has(this.provider);

    const requestBody: Record<string, unknown> = {
      model: this.model,
      temperature: 0.1,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        {
          role: "user",
          content: JSON.stringify({
            url: context.url,
            hostname: context.urlSignals.hostname,
            urlSignals: context.urlSignals,
            pageSignals: context.pageSignals ?? null,
            redirectSignals: context.redirectSignals ?? null,
            domainSignals: context.domainSignals ?? null,
          }),
        },
      ],
    };
    if (useJsonMode) requestBody["response_format"] = { type: "json_object" };

    let completion: OpenAI.Chat.Completions.ChatCompletion;
    try {
      completion = (await this.client.chat.completions.create(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        requestBody as any,
        { timeout: this.timeoutMs },
      )) as OpenAI.Chat.Completions.ChatCompletion;
    } catch (error) {
      throw mapProviderError(error);
    }

    const raw = completion.choices[0]?.message?.content;
    if (!raw) {
      throw new ApiError(502, "invalid_ai_response", "AI returned an empty response.");
    }

    // Providers without json_mode sometimes wrap output in ```json ... ```.
    const cleaned = raw
      .trim()
      .replace(/^```(?:json)?/i, "")
      .replace(/```$/i, "")
      .trim();

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(cleaned);
    } catch {
      throw new ApiError(502, "invalid_ai_response", "AI returned malformed JSON.");
    }

    const result = aiAnalysisResultSchema.safeParse(parsedJson);
    if (!result.success) {
      throw new ApiError(
        502,
        "invalid_ai_response",
        "AI response failed schema validation.",
      );
    }
    return result.data;
  }
}

function mapProviderError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;

  if (typeof error === "object" && error !== null && "status" in error) {
    const status = (error as { status: unknown }).status;
    if (status === 401 || status === 403) {
      return new ApiError(502, "unauthorized", "AI provider authentication failed.");
    }
    if (status === 429) {
      return new ApiError(429, "rate_limited", "AI provider rate limit reached.");
    }
    if (typeof status === "number" && status >= 500) {
      return new ApiError(502, "upstream_error", "AI provider is unavailable.");
    }
  }

  if (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    (error as { name: string }).name === "APIConnectionTimeoutError"
  ) {
    return new ApiError(504, "timeout", "AI request timed out.");
  }

  return new ApiError(502, "upstream_error", "AI analysis failed.");
}

// ---------------------------------------------------------------------------
// Backward-compatible alias (kept so existing imports keep working).
// ---------------------------------------------------------------------------

/** @deprecated Use AiAnalyzer instead. */
export { AiAnalyzer as OpenAIAnalyzer };
export type { AiAnalyzerConfig as OpenAIAnalyzerConfig };
