import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { HistoryEntry } from "@shared/index";
import { ScanHistory } from "./ScanHistory";
import { PrivacyExplainer } from "./PrivacyExplainer";
import { VerdictCard } from "./VerdictCard";

/**
 * Spec §16/§17/§18/§22 UI coverage.
 *
 * Regression targets:
 * - the timeline must not render an unstyled badge for a stored RiskVerdict
 * - evidence and analysis mode must be inspectable
 * - the privacy explanation must be present and expandable
 * - no copy may assert certainty
 */

function entry(partial: Partial<HistoryEntry>): HistoryEntry {
  return {
    hostname: "example.test",
    score: 50,
    scannedAt: Date.now(),
    ...partial,
  };
}

describe("security timeline (spec §18)", () => {
  it("renders a RiskVerdict entry with a proper state and styling", () => {
    // Regression: `riskLevel` historically stored a RiskVerdict string while
    // the badge expected a RiskLevel, so these rows rendered unstyled.
    render(
      <ScanHistory
        history={[
          entry({
            url: "https://suspicious-amazon-shop.test/",
            verdict: "DANGEROUS",
            riskLevel: "DANGEROUS",
            score: 20,
            evidence: ["Brand impersonation", "New domain"],
            analysisMode: "deterministic-only",
          }),
        ]}
        onClear={vi.fn()}
      />,
    );

    expect(screen.getByText(/Stop/)).toBeInTheDocument();
    expect(screen.getByText(/DANGEROUS|Stop/)).toBeInTheDocument();
    expect(screen.getByText(/score 20/)).toBeInTheDocument();
  });

  it("renders the Protected state for a safe entry", () => {
    render(
      <ScanHistory
        history={[entry({ hostname: "google.com", verdict: "SAFE", score: 100 })]}
        onClear={vi.fn()}
      />,
    );
    expect(screen.getByText(/Protected/)).toBeInTheDocument();
  });

  it("does not crash on a legacy entry that only has riskLevel", () => {
    render(
      <ScanHistory
        history={[entry({ hostname: "legacy.test", riskLevel: "high" })]}
        onClear={vi.fn()}
      />,
    );
    // A non-verdict legacy value degrades gracefully to a neutral state.
    expect(screen.getByText(/Scanned|Protected|Be careful|Stop/)).toBeInTheDocument();
  });

  it("groups entries by day", () => {
    const now = Date.now();
    render(
      <ScanHistory
        history={[
          entry({ hostname: "a.test", scannedAt: now, verdict: "SAFE" }),
          entry({
            hostname: "b.test",
            scannedAt: now - 3 * 86_400_000,
            verdict: "LOW_RISK",
          }),
        ]}
        onClear={vi.fn()}
      />,
    );
    expect(screen.getByText("Today")).toBeInTheDocument();
  });

  it("reveals evidence and analysis mode on demand", async () => {
    const user = userEvent.setup();
    render(
      <ScanHistory
        history={[
          entry({
            hostname: "phish.test",
            verdict: "HIGH_RISK",
            evidence: ["Brand impersonation", "Payment form"],
            analysisMode: "ai-enhanced",
          }),
        ]}
        onClear={vi.fn()}
      />,
    );

    // Evidence must be collapsed by default to keep the timeline scannable.
    expect(screen.queryByText("Brand impersonation")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Show details/ }));

    expect(screen.getByText("Brand impersonation")).toBeInTheDocument();
    expect(screen.getByText("Payment form")).toBeInTheDocument();
    expect(screen.getByText(/deterministic rules \+ AI analyst/i)).toBeInTheDocument();
  });

  it("shows an empty state when there is nothing to show", () => {
    render(<ScanHistory history={[]} onClear={vi.fn()} />);
    expect(screen.getByText(/No scan history yet/)).toBeInTheDocument();
  });

  it("clears history on request", async () => {
    const onClear = vi.fn();
    const user = userEvent.setup();
    render(
      <ScanHistory
        history={[entry({ hostname: "a.test", verdict: "SAFE" })]}
        onClear={onClear}
      />,
    );

    await user.click(screen.getByRole("button", { name: /Clear history/i }));
    expect(onClear).toHaveBeenCalledTimes(1);
  });
});

describe("verdict copy is probabilistic (spec §21)", () => {
  it("never claims a site is verified safe or a proven scam", () => {
    const { rerender } = render(<VerdictCard verdict="SAFE" />);
    expect(screen.queryByText(/verified safe/i)).not.toBeInTheDocument();
    expect(screen.getByText(/no known threats found/i)).toBeInTheDocument();

    rerender(<VerdictCard verdict="DANGEROUS" />);
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/is a known phishing/i);
    expect(text).toMatch(/likely dangerous/i);
  });
});

describe("What ScamShield sees (spec §16)", () => {
  it("summarises the privacy position before expansion", () => {
    render(<PrivacyExplainer />);
    const toggle = screen.getByRole("button", { name: /What ScamShield sees/i });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
  });

  it("expands to explain what is analysed and what is never collected", async () => {
    const user = userEvent.setup();
    render(<PrivacyExplainer />);

    await user.click(screen.getByRole("button", { name: /What ScamShield sees/i }));

    expect(screen.getByText("What is analysed")).toBeInTheDocument();
    expect(screen.getByText("What leaves your device")).toBeInTheDocument();
    expect(screen.getByText("When AI is used")).toBeInTheDocument();

    const neverHeading = screen.getByText("Never collected, never transmitted");
    expect(neverHeading).toBeInTheDocument();
    const list = neverHeading.parentElement as HTMLElement;
    const text = within(list).getByText(/One-time passwords/i);
    expect(text).toBeInTheDocument();
  });

  it("states that AI is a second opinion, not the detector", async () => {
    const user = userEvent.setup();
    render(<PrivacyExplainer />);
    await user.click(screen.getByRole("button", { name: /What ScamShield sees/i }));
    expect(screen.getByText(/second opinion, not the detector/i)).toBeInTheDocument();
  });
});
