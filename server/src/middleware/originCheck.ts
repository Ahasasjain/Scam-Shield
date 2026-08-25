import type { RequestHandler } from "express";
import { ApiError } from "./errorHandler.js";

/**
 * CORS/origin lockdown: only requests from the allow-listed Chrome
 * extension origins are accepted on the AI endpoint. When no origins are
 * configured (development), all chrome-extension:// origins are allowed.
 */
export function createOriginCheck(allowedOrigins: string[]): RequestHandler {
  return (req, res, next) => {
    const origin = req.headers.origin;

    if (!origin) {
      // Non-browser clients (curl etc.) — reject in production.
      if (process.env.NODE_ENV === "production") {
        next(new ApiError(403, "unauthorized", "Missing origin header."));
        return;
      }
      next();
      return;
    }

    let allowed: boolean;
    if (allowedOrigins.length > 0) {
      allowed = allowedOrigins.includes(origin);
    } else {
      allowed = origin.startsWith("chrome-extension://");
    }

    if (!allowed) {
      next(new ApiError(403, "unauthorized", "Origin not allowed."));
      return;
    }

    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    next();
  };
}
