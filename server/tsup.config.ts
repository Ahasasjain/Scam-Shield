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
  // External: true runtime node_modules deps only. The @scamshield/shared
  // workspace package ships raw TypeScript (main points at src/index.ts),
  // so it MUST be bundled — leaving it external makes `node dist/index.js`
  // crash with ERR_UNKNOWN_FILE_EXTENSION at runtime.
  external: ["openai", "express", "helmet", "cors", "express-rate-limit", "pino"],
  noExternal: [/@scamshield\/shared/],
});
