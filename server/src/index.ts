import "dotenv/config";
import express from "express";
import helmet from "helmet";
import { createAnalyzeRouter } from "./routes/analyze.js";
import { createHealthRouter } from "./routes/health.js";
import { createRateLimiter } from "./middleware/rateLimit.js";
import { createOriginCheck } from "./middleware/originCheck.js";
import { errorHandler, notFoundHandler } from "./middleware/errorHandler.js";
import { OpenAIAnalyzer } from "./services/openaiAnalyzer.js";
import { logger } from "./lib/logger.js";

interface Env {
  PORT: string;
  AI_API_KEY: string;
  AI_MODEL: string;
  ALLOWED_EXTENSION_ORIGINS: string;
  RATE_LIMIT_MAX: string;
  RATE_LIMIT_WINDOW_MINUTES: string;
}

function loadEnv(): Env {
  const env: Env = {
    PORT: process.env["PORT"] ?? "8787",
    AI_API_KEY: process.env["AI_API_KEY"] ?? "",
    AI_MODEL: process.env["AI_MODEL"] ?? "gpt-4o-mini",
    ALLOWED_EXTENSION_ORIGINS: process.env["ALLOWED_EXTENSION_ORIGINS"] ?? "",
    RATE_LIMIT_MAX: process.env["RATE_LIMIT_MAX"] ?? "20",
    RATE_LIMIT_WINDOW_MINUTES: process.env["RATE_LIMIT_WINDOW_MINUTES"] ?? "15",
  };

  if (!env.AI_API_KEY) {
    logger.warn(
      "AI_API_KEY is not set — /api/analyze will return errors until it is configured.",
    );
  }
  return env;
}

function createApp(env: Env): express.Express {
  const app = express();

  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(helmet());
  app.use(express.json({ limit: "32kb" })); // payloads are tiny by design

  const allowedOrigins = env.ALLOWED_EXTENSION_ORIGINS.split(",")
    .map((o) => o.trim())
    .filter(Boolean);

  app.use(createOriginCheck(allowedOrigins));
  app.use(
    createRateLimiter(
      Number(env.RATE_LIMIT_MAX),
      Number(env.RATE_LIMIT_WINDOW_MINUTES),
    ),
  );

  const analyzer = new OpenAIAnalyzer({
    apiKey: env.AI_API_KEY,
    model: env.AI_MODEL,
  });

  app.use(createHealthRouter());
  app.use(createAnalyzeRouter(analyzer));
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

const env = loadEnv();
const app = createApp(env);

const server = app.listen(Number(env.PORT), () => {
  logger.info(`ScamShield API listening on port ${env.PORT}`);
});

// Graceful shutdown
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    logger.info(`${signal} received — shutting down`);
    server.close(() => process.exit(0));
  });
}
