/** The fetch wrapper calls the hst backend at the single origin /api. */

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly detail?: Record<string, unknown>;
  readonly currentRevision?: number;
  readonly references: string[];

  constructor(status: number, message: string, body?: Record<string, unknown>) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = typeof body?.code === "string" ? body.code : undefined;
    this.detail = body?.detail && typeof body.detail === "object" && !Array.isArray(body.detail)
      ? body.detail as Record<string, unknown> : undefined;
    this.currentRevision = typeof body?.current_revision === "number" ? body.current_revision : undefined;
    this.references = Array.isArray(body?.references)
      ? body.references.filter((value): value is string => typeof value === "string") : [];
  }
}

export type Method = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

export interface ApiOptions {
  method?: Method;
  body?: unknown;
  /** Skip the onUnauthorized hook for this call even on a 401 response. */
  skipUnauthorizedHook?: boolean;
}

const MUTATING: ReadonlySet<Method> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

let onUnauthorized: (() => void) | null = null;

export function setOnUnauthorized(fn: (() => void) | null): void {
  onUnauthorized = fn;
}

async function extractError(res: Response): Promise<ApiError> {
  try {
    const body: unknown = await res.json();
    if (body && typeof body === "object" && "error" in body) {
      const err = (body as { error: unknown }).error;
      if (typeof err === "string") return new ApiError(res.status, err, body as Record<string, unknown>);
    }
  } catch {
    // body is not JSON or is empty
  }
  return new ApiError(res.status, res.statusText || `request failed with status ${res.status}`);
}

export interface ApiDownload {
  blob: Blob;
  filename: string;
  headers: Headers;
}

function filenameFrom(headers: Headers, fallback: string): string {
  const disposition = headers.get("Content-Disposition") ?? "";
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  return match ? match[1] : fallback;
}

export async function apiDownload(
  path: string,
  opts: ApiOptions & { fallbackFilename?: string } = {},
): Promise<ApiDownload> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (MUTATING.has(method)) {
    headers["X-HST-CSRF"] = "1";
  }

  const res = await fetch(`/api${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  if (res.status === 401 && !opts.skipUnauthorizedHook) {
    onUnauthorized?.();
  }
  if (!res.ok) {
    throw await extractError(res);
  }

  return {
    blob: await res.blob(),
    filename: filenameFrom(res.headers, opts.fallbackFilename ?? "download"),
    headers: res.headers,
  };
}

export async function api<T>(path: string, opts: ApiOptions = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (MUTATING.has(method)) {
    headers["X-HST-CSRF"] = "1";
  }

  const res = await fetch(`/api${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  if (res.status === 401 && !opts.skipUnauthorizedHook) {
    onUnauthorized?.();
  }

  if (!res.ok) {
    throw await extractError(res);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** Stable query identity includes every MTU input, including false DF. */
export function mtuQueryParams(mtu?: import("./types").MtuRequest): URLSearchParams {
  const params = new URLSearchParams();
  if (!mtu) return params;
  for (const key of ["mode", "ip_packet_bytes", "ipv4_df", "reply_ip_packet_bytes", "traffic_class"] as const) {
    const value = mtu[key];
    if (value !== undefined && value !== null) params.set(`mtu_${key}`, String(value));
  }
  return params;
}
