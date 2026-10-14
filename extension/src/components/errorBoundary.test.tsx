import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AIAnalysis } from "@/components/AIAnalysis";

function Boom(): never {
  throw new Error("render crash");
}

function silenceReactErrors<T>(renderFn: () => T): T {
  const consoleError = console.error;
  console.error = vi.fn();
  try {
    return renderFn();
  } finally {
    console.error = consoleError;
  }
}

describe("ErrorBoundary", () => {
  it("renders a reload affordance instead of a blank panel on crash", () => {
    silenceReactErrors(() =>
      render(
        <ErrorBoundary>
          <Boom />
        </ErrorBoundary>,
      ),
    );
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Reload panel/i }),
    ).toBeInTheDocument();
  });

  it("renders children normally when nothing crashes", () => {
    render(
      <ErrorBoundary>
        <p>healthy</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText("healthy")).toBeInTheDocument();
  });
});

describe("AIAnalysis hardening", () => {
  it("degrades gracefully on a malformed AI payload instead of crashing", () => {
    render(<AIAnalysis ai={{ status: "enabled", result: { bogus: true } }} />);
    expect(screen.getByText("AI analysis unavailable.")).toBeInTheDocument();
    expect(screen.getByText(/unexpected response/i)).toBeInTheDocument();
  });
});
