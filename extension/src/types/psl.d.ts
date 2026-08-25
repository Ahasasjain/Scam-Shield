/**
 * Ambient type declaration for the `psl` package.
 *
 * psl@1.15.0 ships `types/index.d.ts` but its package.json "exports" map
 * lacks a "types" condition, so TypeScript cannot resolve the declarations
 * under moduleResolution "bundler". This shim declares the minimal surface
 * ScamShield uses.
 */
declare module "psl" {
  export interface ParsedDomain {
    domain: string | null;
    subdomain: string | null;
    suffix: string | null;
    isIcann: boolean;
    isPrivate: boolean;
  }
  export function get(domain: string): string | null;
  export function parse(domain: string): ParsedDomain;
}
