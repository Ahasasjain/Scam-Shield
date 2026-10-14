import { z } from "zod";
import type { RiskVerdict } from "./risk.js";
import type {
  AnalysisMode,
  DetectionCoverageV2,
  Evidence,
  EvidenceConfidence,
  SafeBrowsingStatus,
} from "./evidence.js";

export * from "./risk.js";
export * from "./evidence.js";

/**
 * Zod schemas for every trust boundary:
 * - extension → server (`analyzeRequestSchema`)
 * - server → extension (`aiAnalysisResponseSchema`)
 * - server → Groq (response output validated before it reaches the extension)
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
  formActions: z
    .array(
      z.object({
        actionOrigin: z.string().nullable(),
        isCrossOrigin: z.boolean(),
        containsPassword: z.boolean(),
        containsPaymentFields: z.boolean(),
        /** §3 sensitive categories collected by this form. */
        kinds: z.array(z.string().max(32)).max(10).optional(),
      }),
    )
    .max(20)
    .optional(),
  /** §3: union of sensitive categories present anywhere on the page. */
  sensitiveKinds: z.array(z.string().max(32)).max(10).optional(),
  crossOriginSensitiveForms: z.number().int().nonnegative().optional(),
  offDomainSensitiveForms: z.number().int().nonnegative().optional(),
  suspiciousDownloadCount: z.number().int().nonnegative().optional(),
});

export const domainIdentitySchema = z.object({
  registrableDomain: z.string().nullable(),
  relationship: z.enum([
    "official",
    "trusted-subdomain",
    "brand-in-subdomain",
    "lookalike",
    "brand-in-path",
    "unrelated",
  ]),
  detectedBrand: z.string().optional(),
  matchedOfficialDomain: z.string().optional(),
  similarity: z.number().min(0).max(1).optional(),
});

export const redirectSignalsSchema = z.object({
  chainLength: z.number().int().nonnegative(),
  crossOriginHops: z.number().int().nonnegative(),
  finalUrl: z.string(),
});

export const domainSignalsSchema = z.discriminatedUnion("available", [
  z.object({
    available: z.literal(true),
    domainAgeDays: z.number().int().nonnegative().optional(),
    registrar: z.string().nullable().optional(),
    source: z.literal("rdap"),
  }),
  z.object({
    available: z.literal(false),
    reason: z.string(),
  }),
]);

export const scanContextSchema = z.object({
  url: z.string().url(),
  urlSignals: urlSignalsSchema,
  pageSignals: pageSignalsSchema.optional(),
  redirectSignals: redirectSignalsSchema.optional(),
  domainSignals: domainSignalsSchema.optional(),
  domainIdentity: domainIdentitySchema.optional(),
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
        "not_found",
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
  /** Bypass the background scan cache and force a fresh analysis. */
  force: z.boolean().optional(),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;

export type ExtensionMessage =
  | { type: "SCAN_WEBSITE"; payload: ScanRequest }
  | { type: "GET_SETTINGS" }
  | { type: "GET_LAST_SCAN"; payload: ScanRequest }
  | { type: "PAGE_NAVIGATED"; url: string };

/**
 * Reuses the verdict the background worker already computed for a tab.
 *
 * Spec §17: opening the UI for a meaningful-risk verdict must show the
 * ALREADY-GENERATED result and must NOT trigger another scan. A second scan
 * would re-inject the content script, repeat the RDAP and threat-intel
 * lookups, spend another AI call, and append a duplicate history entry.
 */
export interface LastScanPayload {
  score: number;
  riskLevel: string;
  verdict: RiskVerdict;
  coverage: Record<string, boolean>;
  coverageV2?: DetectionCoverageV2;
  factors: unknown[];
  ai:
    | { status: "enabled"; result: unknown }
    | { status: "unavailable"; reason: string }
    | { status: "disabled" };
  scannedUrl: string;
  durationMs: number;
  confidence?: EvidenceConfidence;
  analysisMode?: AnalysisMode;
  safeBrowsingStatus?: SafeBrowsingStatus;
  evidence?: Evidence[];
  aiAvailable?: boolean;
  limitations: string[];
  breakdown: { category: string; label: string; points: number }[];
}

export interface ScanRiskStateMessage {
  type: "SET_SCAN_RISK_STATE";
  verdict: RiskVerdict;
  showWarning?: boolean;
}

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
  // --- Spec §12 structured result -----------------------------------------
  verdict?: RiskVerdict;
  confidence?: EvidenceConfidence;
  analysisMode?: AnalysisMode;
  safeBrowsingStatus?: SafeBrowsingStatus;
  evidence?: Evidence[];
  coverageV2?: DetectionCoverageV2;
}

export type ScanFailureCode =
  | "unsupported_page"
  | "invalid_url"
  | "scan_failed"
  | "tab_not_found"
  | "stale_scan";

export type ExtensionResponse<T> =
  | { ok: true; data: T }
  | { ok: false; error: { code: string; message: string } };

// ---------------------------------------------------------------------------
// Settings & history (persisted in chrome.storage.local)
// ---------------------------------------------------------------------------

export type ThemeSetting = "light" | "dark" | "system";

export interface ExtensionSettings {
  autoScan: boolean;
  theme: ThemeSetting;
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  autoScan: true,
  theme: "system",
};

export interface HistoryEntry {
  /** Full URL for auditability; optional for entries created before this field existed. */
  url?: string;
  hostname: string;
  score: number;
  /**
   * Legacy score-band label. Kept for backward compatibility with entries
   * written before `verdict` existed. NEW WRITES MUST NOT populate this with
   * a `RiskVerdict` — the two enums are different and mixing them rendered
   * unstyled badges in the timeline.
   */
  riskLevel?: string;
  /** The authoritative verdict. New entries always set this. */
  verdict?: RiskVerdict;
  /** Short evidence titles shown in the security timeline (spec §18). */
  evidence?: string[];
  /** Whether this scan used the AI analyst (spec §18). */
  analysisMode?: AnalysisMode;
  scannedAt: number;
}

export const HISTORY_LIMIT = 50;
