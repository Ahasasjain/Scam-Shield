/**
 * Evidence model (spec §10).
 *
 * Every detection signal is expressed as a structured `Evidence` item so that
 * a developer can answer "why did ScamShield classify this website as
 * dangerous?" by inspecting the evidence alone (spec §20).
 *
 * Design notes:
 * - `Evidence` is the *canonical* model. `RiskFactor` (see risk.ts) predates
 *   it and remains the scoring currency for backward compatibility; factors
 *   are projections of evidence.
 * - `confidence` is deliberately separate from `severity`. A critical-severity
 *   signal can still be low-confidence (heuristic), and vice versa.
 * - `metadata` is a bounded, non-sensitive record. It must never contain form
 *   values, cookies, tokens, or page text (spec §16, rule 1 of §21).
 */

import { z } from "zod";

/** Structured evidence categories (spec §10). */
export const EVIDENCE_TYPES = [
  "SAFE_BROWSING_MATCH",
  "THREAT_INTEL_MATCH",
  "LOOKALIKE_DOMAIN",
  "BRAND_IMPERSONATION",
  "NEW_DOMAIN",
  "EXTERNAL_FORM_SUBMISSION",
  "CREDENTIAL_FORM",
  "PAYMENT_FORM",
  "SUSPICIOUS_REDIRECT",
  "URGENCY_LANGUAGE",
  "CROSS_ORIGIN_FORM",
  "SUSPICIOUS_DOWNLOAD",
  "SUSPICIOUS_SCRIPT",
  "WEAK_HTTPS",
  "UNSTRUCTURED_URL",
  "DECEPTIVE_CONTENT",
  "UNCLASSIFIED",
] as const;

export type EvidenceType = (typeof EVIDENCE_TYPES)[number];

/**
 * Where the evidence came from. The spec wants provenance beyond
 * "rule | ai" so that a UI can say "Google Safe Browsing flagged this"
 * versus "a local heuristic fired".
 */
export const EVIDENCE_SOURCES = [
  "safe_browsing",
  "threat_feed",
  "local_feed",
  "rdap",
  "dns",
  "tls",
  "rule",
  "correlation",
  "brand_intelligence",
  "page_analysis",
  "ai",
] as const;

export type EvidenceSource = (typeof EVIDENCE_SOURCES)[number];

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type EvidenceSeverity = (typeof SEVERITIES)[number];

/**
 * How much we trust the evidence itself, independent of how bad it is.
 * - `confirmed`  : authoritative provider verdict (Safe Browsing, OpenPhish).
 * - `high`       : deterministic rule fired on hard signals.
 * - `medium`     : deterministic rule on soft signals.
 * - `low`        : heuristic / weak signal.
 * - `unknown`    : the check could not be completed (never implies safety).
 */
export const EVIDENCE_CONFIDENCES = [
  "confirmed",
  "high",
  "medium",
  "low",
  "unknown",
] as const;
export type EvidenceConfidence = (typeof EVIDENCE_CONFIDENCES)[number];

/**
 * Explicit Safe Browsing states (spec §2). A no-match is NOT proof of safety,
 * and an outage must be distinguishable from a clean result.
 */
export const SAFE_BROWSING_STATUSES = [
  "KNOWN_MALICIOUS",
  "NO_KNOWN_THREAT",
  "LOOKUP_UNAVAILABLE",
  "UNKNOWN",
] as const;
export type SafeBrowsingStatus = (typeof SAFE_BROWSING_STATUSES)[number];

export const evidenceSeveritySchema = z.enum(SEVERITIES);
export const evidenceConfidenceSchema = z.enum(EVIDENCE_CONFIDENCES);
export const evidenceTypeSchema = z.enum(EVIDENCE_TYPES);
export const evidenceSourceSchema = z.enum(EVIDENCE_SOURCES);
export const safeBrowsingStatusSchema = z.enum(SAFE_BROWSING_STATUSES);

/**
 * Bounded, non-sensitive supplemental detail. Free-form on purpose (spec §10
 * says `metadata`), but capped and restricted to JSON scalars so it can never
 * become a dumping ground for page content.
 */
export const evidenceMetadataSchema = z
  .record(
    z.string().max(64),
    z.union([z.string().max(300), z.number(), z.boolean(), z.null()]),
  )
  .optional();

export const evidenceSchema = z.object({
  /** Stable id; also the scoring-group key (see utils/scoring.ts#groupOf). */
  id: z.string().min(1).max(64),
  type: evidenceTypeSchema,
  severity: evidenceSeveritySchema,
  confidence: evidenceConfidenceSchema,
  source: evidenceSourceSchema,
  title: z.string().min(1).max(200),
  description: z.string().min(1).max(1000),
  metadata: evidenceMetadataSchema,
});

export type Evidence = z.infer<typeof evidenceSchema>;
export type EvidenceMetadata = z.infer<typeof evidenceMetadataSchema>;

/**
 * Which analysis layers actually produced data for a scan (spec §12).
 * Mirrors the existing `DetectionCoverage` but is a superset that also carries
 * the Safe Browsing status string, so UNKNOWN can never render as SAFE.
 */
export const detectionCoverageSchema = z.object({
  url: z.boolean(),
  domainIdentity: z.boolean(),
  threatIntel: z.boolean(),
  page: z.boolean(),
  redirects: z.boolean(),
  reputation: z.boolean(),
  safeBrowsing: safeBrowsingStatusSchema,
});

export type DetectionCoverageV2 = z.infer<typeof detectionCoverageSchema>;

/** Whether the AI analyst ran, and if not, why (spec §9, §12). */
export const analysisModeSchema = z.enum([
  "deterministic-only",
  "ai-enhanced",
  "degraded",
]);

export type AnalysisMode = z.infer<typeof analysisModeSchema>;

/**
 * Final structured result (spec §12).
 *
 * This is the payload the background worker produces and the UI consumes.
 * `limitations` must be non-empty whenever coverage is incomplete — an
 * unexplained partial scan is how "unknown" silently degrades into "safe".
 */
export const scanResultSchema = z.object({
  verdict: z.enum([
    "SAFE",
    "LOW_RISK",
    "SUSPICIOUS",
    "HIGH_RISK",
    "DANGEROUS",
    "UNKNOWN",
  ]),
  score: z.number().int().min(0).max(100),
  confidence: evidenceConfidenceSchema,
  analysisMode: analysisModeSchema,
  safeBrowsingStatus: safeBrowsingStatusSchema,
  evidence: z.array(evidenceSchema).max(100),
  aiAvailable: z.boolean(),
  /** Honest explanations of what could NOT be determined. */
  limitations: z.array(z.string().max(300)).max(20),
});

export type ScanResult = z.infer<typeof scanResultSchema>;
