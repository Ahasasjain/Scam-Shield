import { Router } from "express";
import { getFeedStatus } from "../services/openPhishFeed.js";

/** GET /api/health — for uptime monitoring and load-balancer probes. */
export function createHealthRouter(): Router {
  const router = Router();

  router.get("/api/health", (_req, res) => {
    const feed = getFeedStatus();
    res.json({
      ok: true,
      service: "scamshield-api",
      version: "1.0.0",
      time: new Date().toISOString(),
      uptimeSec: Math.floor(process.uptime()),
      // Dependency visibility for operators: a probe that only reports
      // "ok" cannot distinguish "healthy" from "feed down for 3 days".
      // Counts only — no URLs, keys, or request data ever leave here.
      feed: {
        loaded: feed.loaded,
        stale: feed.stale,
        entryCount: feed.entryCount,
      },
    });
  });

  return router;
}
