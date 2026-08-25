import type { DomainSignals } from "@shared/index";
import type { ScanContext } from "./ruleEngine";

/**
 * Domain reputation analyzer (spec §10).
 *
 * V1 intentionally does NOT fabricate domain age / registrar / reputation
 * values. When a backend intelligence provider is configured later, this
 * module is the single integration point.
 */
export async function collectDomainSignals(
  _context: Pick<ScanContext, "urlSignals">,
): Promise<DomainSignals> {
  return {
    available: false,
    reason:
      "Domain intelligence (age, registrar, reputation) is not configured. No values are shown rather than guessed.",
  };
}
