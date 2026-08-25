import { Router } from "express";

/** GET /api/health — for uptime monitoring and load-balancer probes. */
export function createHealthRouter(): Router {
  const router = Router();

  router.get("/api/health", (_req, res) => {
    res.json({
      ok: true,
      service: "scamshield-api",
      time: new Date().toISOString(),
    });
  });

  return router;
}
