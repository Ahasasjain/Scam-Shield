import { logger } from "../lib/logger.js";

/**
 * Provider registry — minimal, env-driven, vendor-neutral.
 *
 * ScamShield speaks the OpenAI Chat Completions protocol, which almost every
 * provider exposes. Everything is controlled via env vars:
 *
 *   AI_PROVIDER  optional preset id: "openrouter" | "openai" | "custom"
 *   AI_BASE_URL  overrides the preset's base URL (required for "custom")
 *   AI_API_KEY   the provider's API key
 *   AI_MODEL     overrides the preset's default model
 *
 * Adding a brand-new provider does NOT require code changes: set
 * AI_PROVIDER=custom plus AI_BASE_URL / AI_MODEL / AI_API_KEY.
 */

export interface ProviderPreset {
  /** Stable identifier used by `AI_PROVIDER`. */
  readonly id: string;
  /** Human-friendly name shown in logs. */
  readonly displayName: string;
  /** Default base URL. Used when `AI_BASE_URL` is empty. */
  readonly baseUrl: string;
  /** Default model when `AI_MODEL` is empty. */
  readonly defaultModel: string;
}

export const PROVIDERS = {
  openrouter: {
    id: "openrouter",
    displayName: "OpenRouter",
    baseUrl: "https://openrouter.ai/api/v1",
    // Free-tier model that supports structured instruction following.
    // Override with AI_MODEL at any time — no redeploy needed.
    defaultModel: "nvidia/nemotron-3.5-lightning:free",
  },
  openai: {
    id: "openai",
    displayName: "OpenAI",
    baseUrl: "https://api.openai.com/v1",
    defaultModel: "gpt-4o-mini",
  },
  custom: {
    id: "custom",
    displayName: "Custom OpenAI-compatible endpoint",
    baseUrl: "",
    defaultModel: "",
  },
} as const satisfies Record<string, ProviderPreset>;

export type ProviderId = keyof typeof PROVIDERS;

export interface ResolvedProvider {
  provider: ProviderPreset;
  apiKey: string;
  baseUrl: string;
  model: string;
}

/**
 * Resolve the effective provider config from environment variables.
 * Precedence: explicit env value > preset default > empty (logged).
 */
export function resolveProvider(env: NodeJS.ProcessEnv): ResolvedProvider {
  const requested = (env["AI_PROVIDER"] ?? "openrouter").trim().toLowerCase();
  const preset: ProviderPreset =
    requested in PROVIDERS
      ? PROVIDERS[requested as ProviderId]
      : PROVIDERS["custom"];

  if (!(requested in PROVIDERS)) {
    logger.warn(
      { requested },
      "Unknown AI_PROVIDER — treating as custom endpoint (set AI_BASE_URL)",
    );
  }

  const apiKey = (env["AI_API_KEY"] ?? "").trim();
  if (!apiKey) {
    logger.warn(
      { provider: preset.id },
      "AI_API_KEY is empty — AI analysis will fail until configured",
    );
  }

  const baseUrl = (env["AI_BASE_URL"] ?? "").trim() || preset.baseUrl;
  const model = (env["AI_MODEL"] ?? "").trim() || preset.defaultModel;

  if (!baseUrl) {
    throw new Error(
      `No base URL resolved for AI_PROVIDER=${preset.id}. Set AI_BASE_URL in the environment.`,
    );
  }
  if (!model) {
    throw new Error(
      `No model resolved for AI_PROVIDER=${preset.id}. Set AI_MODEL in the environment.`,
    );
  }

  return { provider: preset, apiKey, baseUrl, model };
}
