import axios, {
  AxiosError,
  type AxiosInstance,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from "axios";
import { z } from "zod";

/**
 * Shared axios HTTP client factory (industry-standard patterns):
 * - Centralized instance with base URL + timeout
 * - Request interceptor for correlation IDs and clean headers
 * - Response interceptor mapping every failure to a typed ApiClientError
 * - No secrets, no credentials — payloads are minimal JSON by design
 */

/** Machine-readable error codes shared with the AI analyzer taxonomy. */
export type ApiErrorCode =
  | "network"
  | "timeout"
  | "rate_limited"
  | "unauthorized"
  | "server_error"
  | "invalid_response";

export class ApiClientError extends Error {
  constructor(
    public readonly code: ApiErrorCode,
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "ApiClientError";
  }
}

export interface CreateApiClientOptions {
  baseUrl: string;
  timeoutMs?: number;
}

let correlationCounter = 0;

/**
 * Creates a configured axios instance. Each call site gets its own instance
 * so different backends (or tests) never share interceptors or state.
 */
export function createApiClient(options: CreateApiClientOptions): AxiosInstance {
  const client = axios.create({
    baseURL: options.baseUrl.replace(/\/$/, ""),
    timeout: options.timeoutMs ?? 15_000,
    headers: {
      "Content-Type": "application/json",
      // Custom header identifying the extension client (useful for server metrics).
      "X-ScamShield-Client": "extension/1.0.0",
    },
    // The extension never sends cookies or auth tokens.
    withCredentials: false,
  });

  // Request interceptor: attach a per-request correlation ID for tracing.
  client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    config.headers["X-Request-Id"] = `ss-${Date.now()}-${++correlationCounter}`;
    return config;
  });

  // Response interceptor: unwrap data on success, normalize errors on failure.
  client.interceptors.response.use(
    (response: AxiosResponse) => response,
    (error: unknown) => {
      throw toApiClientError(error);
    },
  );

  return client;
}

/** Maps any thrown value (axios error, abort, unknown) to a typed error. */
export function toApiClientError(error: unknown): ApiClientError {
  if (error instanceof ApiClientError) return error;

  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError;

    if (axiosError.code === "ECONNABORTED") {
      return new ApiClientError("timeout", "Request timed out.");
    }
    if (axiosError.code === "ERR_NETWORK") {
      return new ApiClientError("network", "Network error.", undefined);
    }

    const status = axiosError.response?.status;
    if (status === 429) {
      return new ApiClientError("rate_limited", "Rate limited.", status);
    }
    if (status === 401 || status === 403) {
      return new ApiClientError("unauthorized", "Unauthorized.", status);
    }
    if (typeof status === "number" && status >= 500) {
      return new ApiClientError("server_error", "Server error.", status);
    }
    if (typeof status === "number") {
      return new ApiClientError(
        "invalid_response",
        `Unexpected status ${status}.`,
        status,
      );
    }
  }

  return new ApiClientError("network", "Request failed.");
}

/**
 * Validates an API success envelope at runtime before it reaches callers.
 * Never trust the network layer (spec §16).
 */
export function parseEnvelope<T>(schema: z.ZodType<T>, data: unknown): T {
  const parsed = schema.safeParse(data);
  if (!parsed.success) {
    throw new ApiClientError("invalid_response", "Response failed schema validation.");
  }
  return parsed.data;
}
