import { afterEach, expect, it, vi } from "vitest";
import { api, ApiError } from "./client";

afterEach(() => vi.unstubAllGlobals());

it("preserves inventory recovery information from refused requests", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
    error: "Observed store is unavailable", code: "observed_store_unavailable",
    detail: { cached: { device_uid: "device-1" } },
    current_revision: 7, references: ["target-1"],
  }), { status: 503 })));
  const error = await api("/inventory/devices/device-1").catch((cause: unknown) => cause);
  expect(error).toBeInstanceOf(ApiError);
  expect(error).toMatchObject({ status: 503, code: "observed_store_unavailable",
    detail: { cached: { device_uid: "device-1" } }, currentRevision: 7,
    references: ["target-1"] });
});
