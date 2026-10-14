import {
  aiAnalysisResultSchema,
  analyzeResponseSchema,
  type AiAnalysisResult,
  type ScanContext,
} from "@shared/index";
import {
  ApiClientError,
  createApiClient,
  parseEnvelope,
  type ApiErrorCode,
} from "@/services/api/httpClient";

export type AIAnalyzerStatus =
  | { status: "ok"; result: AiAnalysisResult }
  | { status: "unavailable"; reason: string };

/**
 * Provider-agnostic AI analysis contract (spec §15). The extension never
 * talks to an AI provider directly — implementations call our backend,
 * which holds the API key.
 */
export interface AIAnalyzer {
  analyze(context: ScanContext): Promise<AIAnalyzerStatus>;
}

/** Error taxonomy for AI failures (spec §18). */
export class AIRequestError extends Error {
  constructor(
    public readonly code: ApiErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "AIRequestError";
  }
}

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_RETRIES = 2;

interface HttpAIAnalyzerOptions {
  baseUrl: string;
  timeoutMs?: number;
}

const FAILURE_REASONS: Record<ApiErrorCode, string> = {
  network:
    "Network error contacting the Groq service. Check that the backend is running and reachable.",
  timeout: "AI analysis timed out.",
  rate_limited: "AI rate limit reached. Try again later.",
  unauthorized: "Groq authentication failed. Check GROQ_API_KEY on the backend.",
  upstream_error: "Groq is unavailable. Local security analysis is still available.",
  server_error:
    "Groq reported a server error. Local security analysis is still available.",
  invalid_response: "AI returned an unreadable response.",
};

/**
 * Calls the ScamShield backend `/api/analyze` endpoint via axios.
 * Sends only minimal security metadata (spec §14) — never page contents,
 * credentials, or cookies. Retries with exponential backoff only on
 * network/5xx errors; rate limits and auth failures fail fast.
 */
export class HttpAIAnalyzer implements AIAnalyzer {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(options: HttpAIAnalyzerOptions) {
    this.baseUrl = options.baseUrl;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async analyze(context: ScanContext): Promise<AIAnalyzerStatus> {
    try {
      const result = await this.requestWithRetry(context);
      // Runtime schema validation — never trust AI output (spec §16).
      const parsed = aiAnalysisResultSchema.safeParse(result);
      if (!parsed.success) {
        return { status: "unavailable", reason: "AI returned an invalid response." };
      }
      return { status: "ok", result: parsed.data };
    } catch (error) {
      const code = error instanceof ApiClientError ? error.code : "network";
      return { status: "unavailable", reason: FAILURE_REASONS[code] };
    }
  }

  private async requestWithRetry(context: ScanContext): Promise<unknown> {
    let lastError: ApiClientError = new ApiClientError("network", "Unknown");

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        // Fresh client per attempt so each gets a clean timeout window.
        const client = createApiClient({
          baseUrl: this.baseUrl,
          timeoutMs: this.timeoutMs,
        });
        const response = await client.post("/api/analyze", {
          context: sanitizeContextForTransport(context),
        });
        const envelope = parseEnvelope(analyzeResponseSchema, response.data);
        if (!envelope.ok) {
          const code = envelope.error.code;
          throw new ApiClientError(
            code === "rate_limited"
              ? "rate_limited"
              : code === "unauthorized"
                ? "unauthorized"
                : code === "timeout"
                  ? "timeout"
                  : code === "upstream_error"
                    ? "upstream_error"
                    : code === "server_error"
                      ? "server_error"
                      : "invalid_response",
            envelope.error.message,
          );
        }
        return envelope.result;
      } catch (error) {
        if (!(error instanceof ApiClientError)) throw error;
        lastError = error;
        const retryable = error.code === "network" || error.code === "server_error";
        if (!retryable || attempt === MAX_RETRIES) throw error;
        await sleep(2 ** attempt * 500);
      }
    }
    throw lastError;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sanitizeContextForTransport(context: ScanContext): ScanContext {
  try {
    const url = new URL(context.url);
    // Preserve the existing trailing-slash behavior (no "/" appended when
    // the original URL had none); redact sensitive path segments otherwise.
    const path =
      url.pathname === "/" && !context.url.endsWith("/")
        ? ""
        : redactPath(url.pathname);
    const sanitized: ScanContext = {
      ...context,
      url: `${url.origin}${path}`,
    };
    if (context.pageSignals) {
      sanitized.pageSignals = {
        ...context.pageSignals,
        externalScriptOrigins: context.pageSignals.externalScriptOrigins.slice(0, 50),
        formActions: context.pageSignals.formActions?.map((action) => ({
          ...action,
          actionOrigin: action.actionOrigin ? originOf(action.actionOrigin) : null,
        })),
      };
    }
    return sanitized;
  } catch {
    return { ...context, url: "https://invalid.local/" };
  }
}

function originOf(value: string): string | null {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

const EMAIL_IN_SEGMENT = /[^\s/]*@[^\s/]*/;
const LONG_OPAQUE_SEGMENT = /^[A-Za-z0-9_-]{24,}$/;

/**
 * Client-side path redaction (spec §21 rule 1): password-reset tokens, email
 * addresses, and opaque session ids must not traverse the wire to the backend
 * — even though the server redacts again before the model and never logs
 * bodies. Only the path SHAPE is analytically useful, so values are replaced
 * while the structure is preserved.
 */
function redactPath(pathname: string): string {
  const redacted = pathname
    .split("/")
    .map((segment) => {
      if (segment === "") return segment;
      let value = segment;
      try {
        value = decodeURIComponent(segment);
      } catch {
        // Keep the raw segment on malformed encodings.
      }
      if (EMAIL_IN_SEGMENT.test(value)) return "[email]";
      if (LONG_OPAQUE_SEGMENT.test(value)) return "[token]";
      return segment;
    })
    .join("/");
  return redacted || "/";
}
