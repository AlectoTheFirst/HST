import { describe, expect, it, vi } from "vitest";

vi.mock("../../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/client")>()),
  api: vi.fn(),
}));

import { ApiError, api } from "../../api/client";
import { http } from "./api";

describe("the tile requests", () => {
  it("read a tile that a run does not hold as empty, and pass every other error on", async () => {
    vi.mocked(api).mockRejectedValue(new ApiError(404, "unknown tile block:XD1:wan-edge"));
    await expect(http.tier("render_t2_ports", 1, "block:XD1:wan-edge")).resolves.toEqual([]);
    await expect(http.delta("render_t2_ports", 1, "block:XD1:wan-edge")).resolves.toEqual([]);
    await expect(http.layout(1, "block:XD1:wan-edge")).resolves.toEqual([]);
    await expect(http.layoutDelta(1, "block:XD1:wan-edge")).resolves.toEqual([]);
    await expect(http.tier("render_t1", 1)).rejects.toBeInstanceOf(ApiError);
    vi.mocked(api).mockRejectedValue(new ApiError(500, "server error"));
    await expect(http.layout(1, "block:XD1:wan-edge")).rejects.toBeInstanceOf(ApiError);
  });
});
