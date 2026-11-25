/**
 * `mockApi` matches a request on "METHOD /api/path".
 */

import { vi } from "vitest";

export interface MockRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

export interface MockResponseInit {
  status?: number;
  body?: unknown;
  /** A response body that is not JSON, sent as is. */
  raw?: BodyInit;
  /** Response headers beside the content type. */
  headers?: Record<string, string>;
}

export type MockHandler = (req: MockRequest) => MockResponseInit | Promise<MockResponseInit>;

function toPath(input: RequestInfo | URL): string {
  const url = typeof input === "string" ? input : input.toString();
  try {
    return new URL(url, "http://localhost").pathname;
  } catch {
    return url;
  }
}

function headersToObject(init?: HeadersInit): Record<string, string> {
  const out: Record<string, string> = {};
  new Headers(init).forEach((value, name) => {
    out[name] = value;
  });
  return out;
}

/**
 * A request to a path with no handler throws.
 */
export function mockApi(routes: Record<string, MockHandler>): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const method = (init.method ?? "GET").toUpperCase();
      const path = toPath(input);
      const key = `${method} ${path}`;
      const handler = routes[key];
      if (!handler) {
        throw new Error(`mockApi: no route registered for ${key}`);
      }
      const headers = headersToObject(init.headers);
      const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
      const {
        status = 200,
        body: resBody = {},
        raw,
        headers: resHeaders = {},
      } = await handler({ method, path, headers, body });
      if (raw !== undefined) {
        return new Response(raw, { status, headers: resHeaders });
      }
      return new Response(JSON.stringify(resBody), {
        status,
        headers: { "Content-Type": "application/json", ...resHeaders },
      });
    }),
  );
}
