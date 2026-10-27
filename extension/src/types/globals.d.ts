/**
 * Build-time constants injected by Vite `define` (see vite.config.ts).
 * SCAMSHIELD_API_URL comes from the env var when set; otherwise production
 * builds use the deployed Render API and dev-watch builds use localhost.
 * End users never configure an endpoint.
 */
declare const __SCAMSHIELD_API_URL__: string;
declare const __SCAMSHIELD_AI_ALWAYS_RUN__: boolean;
