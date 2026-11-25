import { describe, it, expect, vi, afterEach } from "vitest";
import { api, ApiError, setOnUnauthorized } from "./client";
import { mockApi } from "../test/fetchMock";

afterEach(() => {
  setOnUnauthorized(null);
});

describe("api client: CSRF header", () => {
  it("sends X-HST-CSRF on POST", async () => {
    let seenHeaders: Record<string, string> = {};
    mockApi({
      "POST /api/thing": (req) => {
        seenHeaders = req.headers;
        return { status: 200, body: { ok: true } };
      },
    });
    await api("/thing", { method: "POST", body: { a: 1 } });
    expect(seenHeaders["x-hst-csrf"]).toBe("1");
  });

  it("does not send X-HST-CSRF on GET", async () => {
    let seenHeaders: Record<string, string> = {};
    mockApi({
      "GET /api/thing": (req) => {
        seenHeaders = req.headers;
        return { status: 200, body: { ok: true } };
      },
    });
    await api("/thing");
    expect(seenHeaders["x-hst-csrf"]).toBeUndefined();
  });

  it.each(["PUT", "PATCH", "DELETE"] as const)("sends X-HST-CSRF on %s", async (method) => {
    let seenHeaders: Record<string, string> = {};
    mockApi({
      [`${method} /api/thing`]: (req) => {
        seenHeaders = req.headers;
        return { status: 200, body: { ok: true } };
      },
    });
    await api("/thing", { method });
    expect(seenHeaders["x-hst-csrf"]).toBe("1");
  });
});

describe("api client: error extraction", () => {
  it("ApiError carries the server's error string and status", async () => {
    mockApi({
      "GET /api/thing": () => ({ status: 404, body: { error: "no thing 'x'" } }),
    });
    await expect(api("/thing")).rejects.toThrow(ApiError);
    try {
      await api("/thing");
      throw new Error("expected api() to reject");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(404);
      expect((err as ApiError).message).toBe("no thing 'x'");
    }
  });

  it("falls back to statusText when the body isn't the {error} shape", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("not json", { status: 500, statusText: "Internal Server Error" }),
      ),
    );
    await expect(api("/thing")).rejects.toThrow("Internal Server Error");
  });
});

describe("api client: 401 handling", () => {
  it("fires the onUnauthorized callback on a 401", async () => {
    mockApi({
      "GET /api/thing": () => ({ status: 401, body: { error: "not authenticated" } }),
    });
    const onUnauthorized = vi.fn();
    setOnUnauthorized(onUnauthorized);
    await expect(api("/thing")).rejects.toThrow("not authenticated");
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("does not fire the callback for non-401 errors", async () => {
    mockApi({
      "GET /api/thing": () => ({ status: 403, body: { error: "requires admin" } }),
    });
    const onUnauthorized = vi.fn();
    setOnUnauthorized(onUnauthorized);
    await expect(api("/thing")).rejects.toThrow("requires admin");
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("skips the callback when skipUnauthorizedHook is set", async () => {
    mockApi({
      "POST /api/login": () => ({ status: 401, body: { error: "invalid credentials" } }),
    });
    const onUnauthorized = vi.fn();
    setOnUnauthorized(onUnauthorized);
    await expect(
      api("/login", { method: "POST", body: {}, skipUnauthorizedHook: true }),
    ).rejects.toThrow("invalid credentials");
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});
