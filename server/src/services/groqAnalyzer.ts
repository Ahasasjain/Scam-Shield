import {
  aiAnalysisResultSchema,
  type AiAnalysisResult,
  type ScanContext,
} from "@scamshield/shared";
import { ApiError } from "../middleware/errorHandler.js";
import { logger } from "../lib/logger.js";
import { z } from "zod";

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const DEFAULT_TIMEOUT_MS = 20_000;

const groqIndicatorSchema = z.object({
  id: z.string().min(1).max(64),
  title: z.string().min(1).max(200),
  description: z.string().min(1).max(1000),
  severity: z.enum(["low", "medium", "high", "critical"]),
  points: z.number().min(0).max(40),
});

const groqResponseSchema = z
  .object({
    verdict: z.enum(["legitimate", "suspicious", "high_risk", "dangerous", "unknown"]),
    confidence: z.number().min(0).max(1),
    brandImpersonation: z.boolean(),
    credentialPhishing: z.boolean(),
    paymentPhishing: z.boolean(),
    socialEngineering: z.boolean(),
    indicators: z.array(groqIndicatorSchema).max(20),
    explanation: z.string().min(1).max(2000),
    recommendedAction: z.enum(["allow", "inform", "warn", "block"]),
  })
  .strict();

const SYSTEM_PROMPT = `You are ScamShield's Groq security-evidence analyst.
Analyze only the sanitized metadata supplied by the application. Never invent facts.
Domain ownership and the final verdict remain deterministic application decisions.
Return ONLY strict JSON with this exact shape:
{
  "verdict": "legitimate|suspicious|high_risk|dangerous|unknown",
  "confidence": 0.0,
  "brandImpersonation": false,
  "credentialPhishing": false,
  "paymentPhishing": false,
  "socialEngineering": false,
  "indicators": [{"id":"string","title":"string","description":"string","severity":"low|medium|high|critical","points":0}],
  "explanation": "string",
  "recommendedAction": "allow|inform|warn|block"
}
Use confidence from 0 to 1. Use only evidence present in the input. Never claim certainty.`;

export interface GroqAnalyzerConfig {
  apiKey: string;
  model: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export class GroqAnalyzer {
  private readonly apiKey: string;
  private readonly model: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(config: GroqAnalyzerConfig) {
    this.apiKey = config.apiKey.trim();
    this.model = config.model;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  async analyze(context: ScanContext): Promise<AiAnalysisResult> {
    if (!this.apiKey) {
      throw new ApiError(
        503,
        "upstream_error",
        "Groq AI credentials are not configured.",
      );
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, this.timeoutMs);
    try {
      const response = await this.fetchImpl(GROQ_URL, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: this.model,
          temperature: 0.1,
          max_tokens: 1200,
          response_format: { type: "json_object" },
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: JSON.stringify(sanitizeContext(context)) },
          ],
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          // Loud on purpose: a dead key disables AI for every user until an
          // operator rotates it. The status code is safe to log; the key never is.
          logger.error(
            { status: response.status },
            "Groq rejected the configured API key — AI analysis is down until GROQ_API_KEY is fixed.",
          );
        }
        if (response.status === 429) {
          throw new ApiError(429, "rate_limited", "Groq rate limit reached.");
        }
        if (response.status >= 500) {
          throw new ApiError(502, "upstream_error", "Groq is temporarily unavailable.");
        }
        throw new ApiError(502, "upstream_error", "Groq request was rejected.");
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new ApiError(502, "invalid_ai_response", "Groq returned invalid JSON.");
      }

      const raw = extractContent(payload);
      const parsed = parseGroqResponse(raw);
      if (!parsed.success) {
        throw new ApiError(
          502,
          "invalid_ai_response",
          "Groq response failed schema validation.",
        );
      }
      return mapGroqResult(parsed.data);
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new ApiError(504, "timeout", "Groq request timed out.");
      }
      if (error instanceof Error && error.name === "AbortError") {
        throw new ApiError(504, "timeout", "Groq request timed out.");
      }
      throw new ApiError(502, "upstream_error", "Groq network request failed.");
    } finally {
      clearTimeout(timeout);
    }
  }
}

function sanitizeContext(context: ScanContext): Record<string, unknown> {
  const pageSignals = context.pageSignals;
  return {
    url: sanitizeUrl(context.url),
    urlSignals: {
      protocol: context.urlSignals.protocol,
      hostname: context.urlSignals.hostname,
      registrableDomain: context.urlSignals.registrableDomain,
      isIpHost: context.urlSignals.isIpHost,
      urlLength: context.urlSignals.urlLength,
      subdomainDepth: context.urlSignals.subdomainDepth,
      hyphenCount: context.urlSignals.hyphenCount,
      hasPunycode: context.urlSignals.hasPunycode,
      tld: context.urlSignals.tld,
      pathLength: context.urlSignals.pathLength,
      isHttps: context.urlSignals.isHttps,
    },
    pageSignals: pageSignals
      ? {
          hasLoginForm: pageSignals.hasLoginForm,
          hasPasswordFieldsOnHttp: pageSignals.hasPasswordFieldsOnHttp,
          hasPaymentForm: pageSignals.hasPaymentForm,
          urgencyLanguageCount: pageSignals.urgencyLanguageCount,
          giveawayPatterns: pageSignals.giveawayPatterns,
          fakeSecurityWarnings: pageSignals.fakeSecurityWarnings,
          externalScriptOrigins: pageSignals.externalScriptOrigins
            .map(sanitizeHostname)
            .filter((origin): origin is string => origin !== null)
            .slice(0, 50),
          formActions: pageSignals.formActions?.slice(0, 20).map((action) => ({
            actionOrigin: action.actionOrigin
              ? sanitizeOrigin(action.actionOrigin)
              : null,
            isCrossOrigin: action.isCrossOrigin,
            containsPassword: action.containsPassword,
            containsPaymentFields: action.containsPaymentFields,
          })),
        }
      : null,
    redirectSignals: context.redirectSignals
      ? {
          chainLength: context.redirectSignals.chainLength,
          crossOriginHops: context.redirectSignals.crossOriginHops,
          finalUrl: sanitizeUrl(context.redirectSignals.finalUrl),
        }
      : null,
    domainSignals: context.domainSignals
      ? context.domainSignals.available
        ? {
            available: true,
            domainAgeDays: context.domainSignals.domainAgeDays,
            registrar: context.domainSignals.registrar,
            source: context.domainSignals.source,
          }
        : { available: false, reason: context.domainSignals.reason }
      : null,
    domainIdentity: context.domainIdentity
      ? {
          registrableDomain: context.domainIdentity.registrableDomain,
          relationship: context.domainIdentity.relationship,
          detectedBrand: context.domainIdentity.detectedBrand,
          matchedOfficialDomain: context.domainIdentity.matchedOfficialDomain,
          similarity: context.domainIdentity.similarity,
        }
      : null,
  };
}

function sanitizeOrigin(value: string): string | null {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function sanitizeHostname(value: string): string | null {
  try {
    const candidate = value.includes("://") ? value : `https://${value}`;
    const hostname = new URL(candidate).hostname.toLowerCase();
    return hostname.length <= 253 ? hostname : null;
  } catch {
    return null;
  }
}

/**
 * Path segments that frequently carry secrets or personal data.
 *
 * Spec §21 rule 1 forbids transmitting tokens and PII to the model. Query
 * strings and fragments are dropped entirely, but a path can hold just as
 * much: `/reset/<token>`, `/u/jane@example.com/verify`, `/orders/4111...`,
 * `/session/eyJhbGciOi...`. The STRUCTURE of a path is useful for risk
 * analysis; the segment VALUES are not, so values are redacted while the
 * shape is preserved (which also keeps pathLength meaningful).
 */
const SENSITIVE_PATH_HINTS = [
  "reset",
  "verify",
  "confirm",
  "token",
  "session",
  "auth",
  "login",
  "signin",
  "password",
  "otp",
  "invite",
  "magic",
  "callback",
  "activate",
  "unsubscribe",
  "order",
  "invoice",
  "payment",
  "card",
  "account",
  "user",
  "profile",
];

const EMAIL_IN_SEGMENT = /[^\s/]*@[^\s/]*/;
const LONG_OPAQUE_SEGMENT = /^[A-Za-z0-9_-]{24,}$/;

function redactSegment(segment: string): string {
  if (segment === "") return segment;

  // An email address embedded in a path is direct PII.
  if (EMAIL_IN_SEGMENT.test(segment)) return "[email]";

  // A long opaque token (JWT, base64 secret, hex id) is not analysable and
  // is high-risk to transmit.
  if (LONG_OPAQUE_SEGMENT.test(segment)) return "[token]";

  // A segment whose NAME hints at sensitive content gets its value hidden.
  const lower = segment.toLowerCase();
  const sensitive = SENSITIVE_PATH_HINTS.some(
    (hint) => lower === hint || lower.startsWith(`${hint}-`) || lower.endsWith(`-${hint}`),
  );
  return sensitive ? "[redacted]" : segment;
}

function sanitizePath(pathname: string): string {
  const redacted = pathname
    .split("/")
    .map((segment) => redactSegment(decodeSegmentSafely(segment)))
    .join("/");
  return redacted || "/";
}

function decodeSegmentSafely(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function sanitizeUrl(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    // Query strings and fragments may contain tokens or personal data, and
    // path segments can too. Origin + redacted path shape is what risk
    // analysis actually needs.
    return `${url.origin}${sanitizePath(url.pathname)}`;
  } catch {
    return "[invalid-url]";
  }
}

function extractContent(payload: unknown): string {
  if (typeof payload !== "object" || payload === null)
    throw new ApiError(502, "invalid_ai_response", "Groq response was malformed.");
  const choices = (payload as { choices?: unknown }).choices;
  const message = Array.isArray(choices)
    ? (choices[0] as { message?: { content?: unknown } } | undefined)?.message
    : undefined;
  if (typeof message?.content !== "string" || !message.content.trim()) {
    throw new ApiError(502, "invalid_ai_response", "Groq returned an empty response.");
  }
  return message.content
    .trim()
    .replace(/^```(?:json)?/i, "")
    .replace(/```$/i, "")
    .trim();
}

function parseGroqResponse(raw: string) {
  try {
    return groqResponseSchema.safeParse(JSON.parse(raw));
  } catch {
    return groqResponseSchema.safeParse(undefined);
  }
}

function mapGroqResult(result: z.infer<typeof groqResponseSchema>): AiAnalysisResult {
  const riskLevel =
    result.verdict === "legitimate"
      ? "safe"
      : result.verdict === "suspicious"
        ? "medium"
        : result.verdict === "high_risk"
          ? "high"
          : result.verdict === "dangerous"
            ? "critical"
            : "low";
  const recommendation = {
    allow: "Proceed with normal caution.",
    inform: "Review the indicators before continuing.",
    warn: "Do not enter passwords, payment details, or personal information.",
    block: "Leave this website and do not enter any information.",
  }[result.recommendedAction];
  // The final projection is validated, not cast: a `.parse()` throw here
  // would otherwise surface as a ZodError, which the error middleware maps
  // to 400 invalid_request — wrongly blaming the client for our mapping bug.
  const projected = aiAnalysisResultSchema.safeParse({
    riskLevel,
    confidence: result.confidence * 100,
    summary: result.explanation,
    indicators: result.indicators,
    recommendation,
  });
  if (!projected.success) {
    throw new ApiError(
      502,
      "invalid_ai_response",
      "Groq response could not be mapped to the analysis contract.",
    );
  }
  return projected.data;
}
