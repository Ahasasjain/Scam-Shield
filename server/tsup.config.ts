import { defineConfig } from "tsup";

/**
 * Server build: bundles the Express API (plus the shared workspace source)
 * into a single ESM output for Node 20. tsup resolves the TS workspace
 * dependency at build time, avoiding NodeNext/tsc emit issues.
 */
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node20",
  outDir: "dist",
  clean: true,
  sourcemap: true,
  // External only true runtime node_modules deps; workspace source is bundled.
  external: ["openai", "express", "helmet", "cors", "express-rate-limit", "pino"],
});
