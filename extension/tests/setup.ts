import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
import { resetChromeMock } from "./mocks/chrome";

afterEach(() => {
  cleanup();
  resetChromeMock();
});
