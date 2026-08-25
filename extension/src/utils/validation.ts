import { z } from "zod";

/**
 * Input validation helpers (spec §27). All external input (URLs, messages,
 * API payloads) passes through these before use.
 */

export const safeUrlSchema = z
  .string()
  .url()
  .refine((url) => /^https?:\/\//i.test(url), {
    message: "Only http(s) URLs can be scanned",
  });

export function validateScanUrl(
  url: string,
): { ok: true; url: string } | { ok: false; reason: string } {
  const parsed = safeUrlSchema.safeParse(url);
  if (!parsed.success) {
    return { ok: false, reason: parsed.error.issues[0]?.message ?? "Invalid URL" };
  }
  return { ok: true, url: parsed.data };
}

/** Basic HTML escaping for any user/site-derived string rendered as text. */
export function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
