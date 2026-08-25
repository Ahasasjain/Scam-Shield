import { z } from "zod";

export * from "./risk.js";

/**
 * Zod schemas for every trust boundary:
 * - extension → server (`analyzeRequestSchema`)
 * - server → extension (`aiAnalysisResponseSchema`)
 * - server → OpenAI (prompt output validated with `aiAnalysisResponseSchema`)
 *
 * Types are inferred from schemas so runtime validation and compile-time
 * types can never drift apart.
 */

// ---------------------------------------------------------------------------
// Signals collected by the extension (minimal, privacy-first metadata only)
// ---------------------------------------------------------------------------

export const urlSignalsSchema = z.object({
  protocol: z.string(),
  hostname: z.string(),
  registrableDomain: z.string(),
  isIpHost: z.boolean(),
  urlLength: z.number().int().nonnegative(),
  subdomainDepth: z.number().int().nonnegative(),
  hyphenCount: z.number().int().nonnegative(),
  hasPunycode: z.boolean(),
  tld: z.string(),
  pathLength: z.number().int().nonnegative(),
  isHttps: z.boolean(),
});

export const pageSignalsSchema = z.object({
  hasLoginForm: z.boolean(),
  hasPasswordFieldsOnHttp: z.boolean(),
  hasPaymentForm: z.boolean(),
  urgencyLanguageCount: z.number().int().nonnegative(),
  giveawayPatterns: z.number().int().nonnegative(),
  fakeSecurityWarnings: z.number().int().nonnegative(),
  externalScriptOrigins: z.array(z.string()).max(50),
});

export const redirectSignalsSchema = z.object({
  chainLength: z.number().int().nonnegative(),
  crossOriginHops: z.number().int().nonnegative(),
  finalUrl: z.string(),
});

export const domainSignalsSchema = z.object({
  /** Domain intelligence is not available in V1 — always reported honestly. */
  available: z.literal(false),
  reason: z.string(),
});

export const scanContextSchema = z.object({
  url: z.string().url(),
  urlSignals: urlSignalsSchema,
  pageSignals: pageSignalsSchema.optional(),
  redirectSignals: redirectSignalsSchema.optional(),
  domainSignals: domainSignalsSchema.optional(),
});

export type UrlSignals = z.infer<typeof urlSignalsSchema>;
export type PageSignals = z.infer<typeof pageSignalsSchema>;
export type RedirectSignals = z.infer<typeof redirectSignalsSchema>;
export type DomainSignals = z.infer<typeof domainSignalsSchema>;
export type ScanContext = z.infer<typeof scanContextSchema>;

// ---------------------------------------------------------------------------
// AI analysis contract (extension → server request)
// ---------------------------------------------------------------------------

export const analyzeRequestSchema = z.object({
  context: scanContextSchema,
});

export type AnalyzeRequest = z.infer<typeof analyzeRequestSchema>;

// ---------------------------------------------------------------------------
// AI analysis contract (server → extension response)
// ---------------------------------------------------------------------------

export const aiIndicatorSchema = z.object({
  id: z.string().min(1).max(64),
  title: z.string().min(1).max(200),
  description: z.string().min(1).max(1000),
  severity: z.enum(["low", "medium", "high", "critical"]),
  points: z.number().min(0).max(40),
});

export const aiAnalysisResultSchema = z.object({
  riskLevel: z.enum(["safe", "low", "medium", "high", "critical"]),
  confidence: z.number().min(0).max(100),
  summary: z.string().min(1).max(2000),
  indicators: z.array(aiIndicatorSchema).max(20),
  recommendation: z.string().min(1).max(1000),
});

export type AiIndicator = z.infer<typeof aiIndicatorSchema>;
export type AiAnalysisResult = z.infer<typeof aiAnalysisResultSchema>;

/** Envelope returned by the Express API. */
export const analyzeResponseSchema = z.discriminatedUnion("ok", [
  z.object({ ok: z.literal(true), result: aiAnalysisResultSchema }),
  z.object({
    ok: z.literal(false),
    error: z.object({
      code: z.enum([
        "invalid_request",
        "rate_limited",
        "unauthorized",
        "upstream_error",
        "timeout",
        "invalid_ai_response",
        "server_error",
      ]),
      message: z.string(),
    }),
  }),
]);

export type AnalyzeResponse = z.infer<typeof analyzeResponseSchema>;

// ---------------------------------------------------------------------------
// Extension message contracts (popup/sidepanel ↔ background)
// ---------------------------------------------------------------------------

export const scanRequestSchema = z.object({
  tabId: z.number().int(),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;

export type ExtensionMessage =
  | { type: "SCAN_WEBSITE"; payload: ScanRequest }
  | { type: "GET_SETTINGS" }
  | { type: "UPDATE_AI_MODE"; payload: { enabled: boolean } };

export type ScanProgressStep =
  | "validating"
  | "collecting"
  | "rules"
  | "ai"
  | "combining"
  | "done";

export interface ScanSuccessPayload {
  score: number;
  riskLevel: string;
  factors: unknown[];
  ai:
    | { status: "enabled"; result: unknown }
    | { status: "unavailable"; reason: string }
    | { status: "disabled" };
  scannedUrl: string;
  durationMs: number;
}

export type ScanFailureCode =
  | "unsupported_page"
  | "invalid_url"
  | "scan_failed"
  | "tab_not_found";

export type ExtensionResponse<T> =
  | { ok: true; data: T }
  | { ok: false; error: { code: string; message: string } };

// ---------------------------------------------------------------------------
// Settings & history (persisted in chrome.storage.local)
// ---------------------------------------------------------------------------

export type ThemeSetting = "light" | "dark" | "system";

export interface ExtensionSettings {
  aiEnabled: boolean;
  autoScan: boolean;
  theme: ThemeSetting;
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  aiEnabled: false,
  autoScan: false,
  theme: "system",
};

export interface HistoryEntry {
  hostname: string;
  score: number;
  riskLevel: string;
  scannedAt: number;
}

export const HISTORY_LIMIT = 50;
