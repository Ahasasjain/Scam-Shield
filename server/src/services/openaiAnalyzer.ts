import OpenAI from "openai";
import {
  aiAnalysisResultSchema,
  type AiAnalysisResult,
  type ScanContext,
} from "@scamshield/shared";
import { ApiError } from "../middleware/errorHandler.js";

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

export interface OpenAIAnalyzerConfig {
  apiKey: string;
  model: string;
  timeoutMs?: number;
}

/**
 * Calls the OpenAI Chat Completions API in JSON mode and validates the
 * response against the shared Zod schema before returning it (spec §16).
 */
export class OpenAIAnalyzer {
  private readonly client: OpenAI;
  private readonly model: string;
  private readonly timeoutMs: number;

  constructor(config: OpenAIAnalyzerConfig) {
    this.client = new OpenAI({
      apiKey: config.apiKey,
      timeout: config.timeoutMs ?? 20_000,
      maxRetries: 1,
    });
    this.model = config.model;
    this.timeoutMs = config.timeoutMs ?? 20_000;
  }

  async analyze(context: ScanContext): Promise<AiAnalysisResult> {
    let completion: OpenAI.Chat.Completions.ChatCompletion;
    try {
      completion = await this.client.chat.completions.create(
        {
          model: this.model,
          response_format: { type: "json_object" },
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
        },
        { timeout: this.timeoutMs },
      );
    } catch (error) {
      throw mapOpenAIError(error);
    }

    const raw = completion.choices[0]?.message?.content;
    if (!raw) {
      throw new ApiError(502, "invalid_ai_response", "AI returned an empty response.");
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(raw);
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

function mapOpenAIError(error: unknown): ApiError {
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
