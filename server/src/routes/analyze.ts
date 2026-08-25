import { Router } from "express";
import { analyzeRequestSchema } from "@scamshield/shared";
import { OpenAIAnalyzer } from "../services/openaiAnalyzer.js";
import { ApiError } from "../middleware/errorHandler.js";

/**
 * POST /api/analyze — validates the request with Zod, calls the AI provider
 * through the analyzer service, and returns a schema-validated result
 * (spec §14–§17, §33).
 */
export function createAnalyzeRouter(analyzer: OpenAIAnalyzer): Router {
  const router = Router();

  router.post("/api/analyze", (req, res, next) => {
    void (async () => {
      const bodyResult = analyzeRequestSchema.safeParse(req.body);
      if (!bodyResult.success) {
        next(new ApiError(400, "invalid_request", "Invalid scan context payload."));
        return;
      }

      try {
        const result = await analyzer.analyze(bodyResult.data.context);
        res.json({ ok: true, result });
      } catch (error) {
        next(error);
      }
    })();
  });

  return router;
}
