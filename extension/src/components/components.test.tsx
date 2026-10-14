import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SecurityScore } from "@/components/SecurityScore";
import { ScanHistory } from "@/components/ScanHistory";
import { RecommendationCard } from "@/components/RecommendationCard";

describe("SecurityScore", () => {
  it("shows the score and probabilistic label for safe sites", () => {
    render(<SecurityScore score={92} riskLevel="safe" />);
    expect(screen.getByText("92")).toBeInTheDocument();
    // spec §43: never claims "definitely safe"
    expect(screen.getByText(/No significant indicators detected/i)).toBeInTheDocument();
  });

  it("has an accessible label", () => {
    render(<SecurityScore score={24} riskLevel="critical" />);
    expect(
      screen.getByRole("img", { name: /score 24 out of 100/i }),
    ).toBeInTheDocument();
  });
});

describe("ScanHistory", () => {
  const entries = [
    {
      hostname: "example.com",
      score: 95,
      // New-shape entry: `verdict` is authoritative, `riskLevel` is legacy.
      verdict: "SAFE" as const,
      riskLevel: "safe",
      scannedAt: Date.parse("2026-01-01T10:00:00Z"),
    },
  ];

  it("renders history entries with the verdict state and score", () => {
    render(<ScanHistory history={entries} onClear={vi.fn()} />);
    expect(screen.getByText("example.com")).toBeInTheDocument();
    expect(screen.getByText(/score 95/)).toBeInTheDocument();
    expect(screen.getByText(/Protected/)).toBeInTheDocument();
  });

  it("shows empty state when no history", () => {
    render(<ScanHistory history={[]} onClear={vi.fn()} />);
    expect(screen.getByText(/No scan history yet/i)).toBeInTheDocument();
  });

  it("clears history on button click", async () => {
    const onClear = vi.fn();
    render(<ScanHistory history={entries} onClear={onClear} />);
    await userEvent.click(screen.getByRole("button", { name: /clear history/i }));
    expect(onClear).toHaveBeenCalledTimes(1);
  });
});

describe("RecommendationCard", () => {
  it("warns about sensitive data on high-risk sites", () => {
    render(<RecommendationCard riskLevel="high" />);
    expect(screen.getByText(/Do not enter passwords/i)).toBeInTheDocument();
  });

  it("uses probabilistic language for safe sites", () => {
    render(<RecommendationCard riskLevel="safe" />);
    expect(
      screen.getByText(/No significant risk indicators detected/i),
    ).toBeInTheDocument();
  });
});
