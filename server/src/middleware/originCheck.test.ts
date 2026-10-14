import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { createOriginCheck } from "./originCheck.js";
import { ApiError } from "./errorHandler.js";

function fakeReq(origin?: string, method = "POST") {
  return { headers: { origin }, method } as never;
}

function fakeRes() {
  const res = {
    statusCode: 200,
    headers: {} as Record<string, string>,
    ended: false,
    setHeader(key: string, value: string) {
      res.headers[key] = value;
    },
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    end() {
      res.ended = true;
    },
  };
  return res;
}

describe("origin check", () => {
  const OLD_ENV = process.env["NODE_ENV"];

  beforeEach(() => {
    delete process.env["NODE_ENV"];
  });

  afterEach(() => {
    if (OLD_ENV === undefined) delete process.env["NODE_ENV"];
    else process.env["NODE_ENV"] = OLD_ENV;
  });

  it("allows an allow-listed extension origin and sets CORS headers", () => {
    const next = vi.fn();
    const res = fakeRes();
    createOriginCheck(["chrome-extension://abc"])(fakeReq("chrome-extension://abc"), res as never, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.headers["Access-Control-Allow-Origin"]).toBe("chrome-extension://abc");
    expect(res.headers["Vary"]).toBe("Origin");
  });

  it("rejects a non-listed origin with 403 unauthorized", () => {
    const next = vi.fn();
    createOriginCheck(["chrome-extension://abc"])(
      fakeReq("https://evil.test"),
      fakeRes() as never,
      next,
    );

    expect(next).toHaveBeenCalledTimes(1);
    const err = next.mock.calls[0]?.[0];
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(403);
  });

  it("allows any chrome-extension:// origin when no allowlist is configured (dev)", () => {
    const next = vi.fn();
    createOriginCheck([])(fakeReq("chrome-extension://anything"), fakeRes() as never, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]?.[0]).toBeUndefined();
  });

  it("rejects web origins when no allowlist is configured", () => {
    const next = vi.fn();
    createOriginCheck([])(fakeReq("https://app.test"), fakeRes() as never, next);
    expect(next.mock.calls[0]?.[0]).toBeInstanceOf(ApiError);
  });

  it("lets Origin-less clients through in development", () => {
    const next = vi.fn();
    createOriginCheck([])(fakeReq(undefined), fakeRes() as never, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]?.[0]).toBeUndefined();
  });

  it("rejects Origin-less clients in production", () => {
    process.env["NODE_ENV"] = "production";
    const next = vi.fn();
    createOriginCheck([])(fakeReq(undefined), fakeRes() as never, next);
    const err = next.mock.calls[0]?.[0];
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(403);
  });

  it("answers CORS preflights with 204 instead of falling through to 404", () => {
    const next = vi.fn();
    const res = fakeRes();
    createOriginCheck([])(fakeReq("chrome-extension://abc", "OPTIONS"), res as never, next);

    expect(res.statusCode).toBe(204);
    expect(res.ended).toBe(true);
    expect(next).not.toHaveBeenCalled();
  });
});
