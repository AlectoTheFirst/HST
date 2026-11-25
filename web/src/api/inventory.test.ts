import { describe, it, expect, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { inventoryApi, ERROR_STATUS, OPERATION_PERMISSIONS, PREVIEW_OPERATIONS } from "./inventory";
import { dependentKeys, inventoryKeys, invalidateAfterInventoryWrite, SITES_GRAPH_KEY } from "../inventory/queryKeys";
import { mockApi } from "../test/fetchMock";

describe("inventory client", () => {
  it("repeats list filters as OR within a field and pins sort, limit and cursor", async () => {
    let seen = "";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        seen = input.toString();
        return new Response(JSON.stringify({ items: [], next_cursor: null, generation: { snapshot_key: null, intent_generation: 1 } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    await inventoryApi.listDevices({ site_id: ["1", "2"], lifecycle: ["missing"], sort: "site", limit: 25, cursor: "abc" });
    const url = new URL(seen, "http://localhost");
    expect(url.pathname).toBe("/api/inventory/devices");
    expect(url.searchParams.getAll("site_id")).toEqual(["1", "2"]);
    expect(url.searchParams.getAll("lifecycle")).toEqual(["missing"]);
    expect(url.searchParams.get("sort")).toBe("site");
    expect(url.searchParams.get("limit")).toBe("25");
    expect(url.searchParams.get("cursor")).toBe("abc");
    expect(url.searchParams.has("q")).toBe(false);
  });

  it("never puts an id with slashes or colons into the path unescaped", async () => {
    let seen = "";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        seen = input.toString();
        return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
      }),
    );
    await inventoryApi.getRoutingGroup("dev:x/vrf:a");
    expect(seen).toBe("/api/inventory/routing-groups/dev%3Ax%2Fvrf%3Aa");
  });

  it("deletes views and routing groups directly with the expected revision", async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        seen.push(`${init?.method} ${input.toString()} ${init?.body ?? ""}`.trim());
        return new Response(null, { status: 204 });
      }),
    );
    await inventoryApi.deleteView("v1", 3);
    await inventoryApi.deleteRoutingGroup("g1", 2);
    expect(seen).toEqual([
      "DELETE /api/inventory/views/v1?expected_revision=3",
      "DELETE /api/inventory/routing-groups/g1?expected_revision=2",
    ]);
  });

  it("sends mutations with the CSRF header and the body verbatim", async () => {
    let request: { headers: Record<string, string>; body: unknown } | null = null;
    mockApi({
      "PATCH /api/inventory/devices/d1/placement": (req) => {
        request = { headers: req.headers, body: req.body };
        return { status: 200, body: { ok: true } };
      },
    });
    await inventoryApi.patchPlacement("d1", { mode: "assigned", site_id: "7", expected_revision: 3 });
    expect(request).not.toBeNull();
    expect(request!.headers["x-hst-csrf"]).toBe("1");
    expect(request!.body).toEqual({ mode: "assigned", site_id: "7", expected_revision: 3 });
  });

  it("freezes the operation enum and its permissions", () => {
    expect(PREVIEW_OPERATIONS).toEqual([
      "place_devices",
      "assign_target_profile",
      "edit_profile",
      "rotate_credential",
      "delete_site",
      "delete_connection",
      "delete_target",
      "replace_target",
      "edit_routing_members",
      "archive_devices",
      "restore_devices",
    ]);
    for (const op of PREVIEW_OPERATIONS) expect(OPERATION_PERMISSIONS[op]).toMatch(/\.write$/);
    expect(ERROR_STATUS.inventory_changed).toBe(409);
    expect(ERROR_STATUS.observed_store_unavailable).toBe(503);
  });
});

describe("inventory query keys", () => {
  it("nests every key under the inventory root", () => {
    expect(inventoryKeys.devices.detail("d")[0]).toBe("inventory");
    expect(inventoryKeys.devices.list({ q: "x" })).toEqual(["inventory", "devices", "list", { q: "x" }]);
    expect(inventoryKeys.targets.effective("t")).toEqual(["inventory", "targets", "effective", "t"]);
  });

  it("invalidates every dependent read of a placement write", async () => {
    const keys = dependentKeys("placement", { deviceId: "d1" });
    expect(keys).toContainEqual(inventoryKeys.devices.all);
    expect(keys).toContainEqual(inventoryKeys.devices.detail("d1"));
    expect(keys).toContainEqual(inventoryKeys.devices.history("d1"));
    expect(keys).toContainEqual(inventoryKeys.sites.all);
    expect(keys).toContainEqual(inventoryKeys.locations.all);
    expect(keys).not.toContainEqual(inventoryKeys.profiles.all);

    const client = new QueryClient();
    const spy = vi.spyOn(client, "invalidateQueries");
    await invalidateAfterInventoryWrite(client, "profile", { profileId: "p1" });
    const invalidated = spy.mock.calls.map((c) => c[0]?.queryKey);
    expect(invalidated).toContainEqual(inventoryKeys.profiles.impact("p1"));
    expect(invalidated).toContainEqual(inventoryKeys.targets.all); // effective settings follow the profile
    expect(invalidated).toContainEqual(inventoryKeys.state());
  });

  it("treats an apply as a generation change that stales every inventory read", () => {
    expect(dependentKeys("apply")).toContainEqual(inventoryKeys.all);
  });

  it("invalidates the estate drawing after a write that moves a site or a device", () => {
    for (const kind of ["placement", "site", "location", "apply"] as const) {
      expect(dependentKeys(kind)).toContainEqual(SITES_GRAPH_KEY);
    }
    expect(dependentKeys("credential")).not.toContainEqual(SITES_GRAPH_KEY);
  });
});
