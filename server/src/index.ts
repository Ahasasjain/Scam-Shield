import { config as loadDotenv } from "dotenv";
import { fileURLToPath } from "node:url";
import path from "node:path";
import express from "express";
import helmet from "helmet";
import { createAnalyzeRouter } from "./routes/analyze.js";
import { createHealthRouter } from "./routes/health.js";
import {
  createThreatLookupRouter,
  startThreatFeed,
  stopThreatFeed,
} from "./routes/threatLookup.js";
import { createRateLimiter } from "./middleware/rateLimit.js";
import { createOriginCheck } from "./middleware/originCheck.js";
import { errorHandler, notFoundHandler } from "./middleware/errorHandler.js";
import { AiAnalyzer } from "./services/openaiAnalyzer.js";
import { resolveProvider } from "./services/aiProviders.js";
import { logger } from "./lib/logger.js";

interface Env {
  PORT: string;
  AI_PROVIDER: string;
  AI_API_KEY: string;
  AI_BASE_URL: string;
  AI_MODEL: string;
  ALLOWED_EXTENSION_ORIGINS: string;
  RATE_LIMIT_MAX: string;
  RATE_LIMIT_WINDOW_MINUTES: string;
}

function loadEnv(): Env {
  const env: Env = {
    PORT: process.env["PORT"] ?? "8787",
    AI_PROVIDER: process.env["AI_PROVIDER"] ?? "",
    AI_API_KEY: process.env["AI_API_KEY"] ?? "",
    AI_BASE_URL: process.env["AI_BASE_URL"] ?? "",
    AI_MODEL: process.env["AI_MODEL"] ?? "",
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

  const resolved = resolveProvider({
    AI_PROVIDER: env.AI_PROVIDER,
    AI_API_KEY: env.AI_API_KEY,
    AI_BASE_URL: env.AI_BASE_URL,
    AI_MODEL: env.AI_MODEL,
  });

  logger.info(
    {
      provider: resolved.provider.id,
      model: resolved.model,
      baseUrl: resolved.baseUrl,
    },
    "AI analyzer configured",
  );

  const analyzer = new AiAnalyzer({
    provider: resolved.provider.id,
    apiKey: resolved.apiKey,
    baseUrl: resolved.baseUrl,
    model: resolved.model,
  });

  app.use(createHealthRouter());
  app.use(createThreatLookupRouter());
  app.use(createAnalyzeRouter(analyzer));
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

// Load .env relative to this file (server/dist at runtime), not the process
// CWD, so the server works whether started from the repo root, server/, or a
// container. In dev (tsx runs src/), this resolves to server/../.env fallback.
const here = path.dirname(fileURLToPath(import.meta.url));
const candidates = [
  path.resolve(here, "../.env"), // dist/index.js -> server/.env
  path.resolve(here, "../../server/.env"), // repo-root start -> server/.env
  path.resolve(here, "../../.env"), // src/index.ts via tsx -> server/.env
];
for (const candidate of candidates) {
  const result = loadDotenv({ path: candidate });
  if (!result.error) break;
  const code = (result.error as NodeJS.ErrnoException).code;
  if (code !== "ENOENT") {
    logger.warn({ err: result.error }, "Failed to load .env file");
  }
}

const env = loadEnv();
const app = createApp(env);

// Start the OpenPhish threat feed refresh cycle.
startThreatFeed();

const server = app.listen(Number(env.PORT), () => {
  logger.info(`ScamShield API listening on port ${env.PORT}`);
});

// Graceful shutdown
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    logger.info(`${signal} received — shutting down`);
    stopThreatFeed();
    server.close(() => process.exit(0));
  });
}
