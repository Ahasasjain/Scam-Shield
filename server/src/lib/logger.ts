import pino from "pino";

/**
 * Structured logging (spec §35). Never log request bodies (they may contain
 * URL/page metadata), API keys, or authorization headers.
 */
export const logger = pino({
  level: process.env["LOG_LEVEL"] ?? "info",
  redact: {
    paths: ["req.headers.authorization", "req.headers.cookie", "*.apiKey", "*.api_key"],
    censor: "[REDACTED]",
  },
  ...(process.env.NODE_ENV !== "production"
    ? { transport: { target: "pino-pretty", options: { colorize: true } } }
    : {}),
});
