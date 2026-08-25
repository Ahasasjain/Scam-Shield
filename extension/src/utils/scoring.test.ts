import { describe, expect, it } from "vitest";
import { calculateScore } from "@/utils/scoring";
import type { RiskFactor } from "@shared/index";

function factor(id: string, points: number): RiskFactor {
  return {
    id,
    title: id,
    description: "test",
    severity: "low",
    points,
    source: "rule",
  };
}

describe("calculateScore", () => {
  it("returns 100 / safe when no factors", () => {
    const result = calculateScore([]);
    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe("safe");
  });

  it("maps score bands correctly (spec §13)", () => {
    // 0–29 critical, 30–49 high, 50–69 medium, 70–84 low, 85+ safe
    expect(calculateScore([factor("url-ip-host", 75)]).riskLevel).toBe("critical"); // 25
    expect(calculateScore([factor("url-ip-host", 60)]).riskLevel).toBe("high"); // 40
    expect(calculateScore([factor("url-ip-host", 40)]).riskLevel).toBe("medium"); // 60
    expect(calculateScore([factor("url-ip-host", 20)]).riskLevel).toBe("low"); // 80
    expect(calculateScore([factor("url-ip-host", 10)]).riskLevel).toBe("safe"); // 90
  });

  it("clamps at zero for extreme deductions", () => {
    const result = calculateScore([factor("a", 150)]);
    expect(result.score).toBe(0);
  });

  it("includes AI factors in the total", () => {
    const aiFactor: RiskFactor = { ...factor("ai-test", 15), source: "ai" };
    const result = calculateScore([factor("url-x", 10)], [aiFactor]);
    expect(result.score).toBe(75);
    expect(result.breakdown.find((b) => b.category === "ai")?.points).toBe(15);
  });

  it("produces a per-category breakdown", () => {
    const result = calculateScore([
      factor("url-ip-host", 18),
      factor("https-not-used", 12),
    ]);
    expect(result.breakdown).toHaveLength(2);
    expect(result.breakdown.map((b) => b.category)).toEqual(
      expect.arrayContaining(["url", "https"]),
    );
  });
});
