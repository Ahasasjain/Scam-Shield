import type { Severity } from "@shared/index";

/**
 * Structured dev logging (spec §35).
 * - Verbose in development (`__DEV__`), silent in production builds.
 * - Callers must never pass passwords, cookies, tokens, or page contents.
 */

declare const __DEV__: boolean;

type LogLevel = "debug" | "info" | "warn" | "error";

function enabled(level: LogLevel): boolean {
  if (typeof __DEV__ !== "undefined" && __DEV__) return true;
  return level === "warn" || level === "error";
}

function emit(level: LogLevel, scope: string, message: string, data?: unknown): void {
  if (!enabled(level)) return;
  const prefix = `[ScamShield:${scope}]`;
  switch (level) {
    case "debug":
    case "info":
      console.info(prefix, message, data ?? "");
      break;
    case "warn":
      console.warn(prefix, message, data ?? "");
      break;
    case "error":
      console.error(prefix, message, data ?? "");
      break;
  }
}

export function createLogger(scope: string) {
  return {
    debug: (message: string, data?: unknown) => emit("debug", scope, message, data),
    info: (message: string, data?: unknown) => emit("info", scope, message, data),
    warn: (message: string, data?: unknown) => emit("warn", scope, message, data),
    error: (message: string, data?: unknown) => emit("error", scope, message, data),
  };
}

/** Severity → display weight, used by UI sorting. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
