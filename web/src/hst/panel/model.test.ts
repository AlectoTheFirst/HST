import { describe, expect, it } from "vitest";
import { createNullRenderer } from "../render/null";
import type { TableName } from "../render/types";
import { base, estate, tile } from "../test/estate";
import { portGroups } from "../data/portGroups";
import { diagramOf, panelOf } from "./model";

function scene() {
  const t = estate({ sites: 2, devices: 6, ports: 2 });
  const r = createNullRenderer();
  r.setTier("layout", base(t));
  for (const name of ["render_t0", "render_t1", "render_t1_edges"] as TableName[]) r.setTier(name, t[name]);
  return r.scene;
}

describe("the side panel", () => {
  const s = scene();

  it("shows a device with its facts and its links", () => {
    const p = panelOf(s, "dev:s0d1", null)!;
    expect(p.kind).toBe("device");
    expect(p.title).toBe("s0d1");
    expect(p.tabs.map((t) => t.name)).toEqual(["Overview", "Ports", "Segments", "Links"]);
    expect(p.tabs[0].facts).toContainEqual(["Site", "s0"]);
    expect(p.tabs[3].items?.map((i) => i.uid).sort()).toEqual(["dev:s0d0", "dev:s0d2", "dev:s1d1"]);
  });

  it("lists the segments with clients of a device in the Segments tab, prefix first", () => {
    const t = estate({ sites: 1, devices: 2, ports: 2 });
    const block = "block:s0:campus";
    t.render_t2_segments.push(
      { uid: "dev:s0d1/segment/bd:10", device_uid: "dev:s0d1", tile: block, vid: 10, name: "users", prefix: "10.1.10.0/24", client_count: 3 },
      { uid: "dev:s0d1/segment/bd:20", device_uid: "dev:s0d1", tile: block, vid: 20, name: "guests", prefix: null, client_count: 1 },
      { uid: "dev:s0d1/segment/bd:30", device_uid: "dev:s0d1", tile: block, vid: 30, name: "empty", prefix: "10.1.30.0/24", client_count: 0 },
    );
    const r = createNullRenderer();
    r.setTier("layout", base(t));
    for (const name of ["render_t0", "render_t1", "render_t1_edges"] as TableName[]) r.setTier(name, t[name]);
    expect(panelOf(r.scene, "dev:s0d1", null)!.tabs[2].facts).toBeTruthy();
    r.setTier("render_t2_segments", tile(t, "render_t2_segments", block), block);
    const tab = panelOf(r.scene, "dev:s0d1", null)!.tabs[2];
    expect(tab.name).toBe("Segments");
    expect(tab.items!.map((i) => [i.uid, i.label, i.meta])).toEqual([
      ["dev:s0d1/segment/bd:10", "10.1.10.0/24", "users, 3 clients"],
      ["dev:s0d1/segment/bd:20", "VLAN 20", "1 clients"],
    ]);
  });

  it("lists the port groups of a device in the Ports tab once its tile is loaded", () => {
    const t = estate({ sites: 1, devices: 3, ports: 60 });
    const r = createNullRenderer();
    r.setTier("layout", base(t));
    for (const name of ["render_t0", "render_t1", "render_t1_edges"] as TableName[]) r.setTier(name, t[name]);
    expect(panelOf(r.scene, "dev:s0d1", null)!.tabs[1].facts).toBeTruthy();
    const block = "block:s0:campus";
    r.setTier("render_t2_ports", tile(t, "render_t2_ports", block), block);
    r.setTier("render_t2_cables", tile(t, "render_t2_cables", block), block);
    r.setTier("render_t2_port_groups", portGroups(tile(t, "render_t2_ports", block), tile(t, "render_t2_cables", block)), block);
    const tab = panelOf(r.scene, "dev:s0d1", null)!.tabs[1];
    expect(tab.name).toBe("Ports");
    expect(tab.items!.length).toBeGreaterThan(0);
    for (const item of tab.items!) {
      expect(item.meta).toMatch(/^\d+ ports/);
      expect(item.uid.startsWith("dev:s0d1/")).toBe(true);
    }
  });

  it("shows a block and a site with their devices", () => {
    const block = panelOf(s, null, "block:s0:campus")!;
    expect(block.kind).toBe("block");
    expect(block.tabs[1].items).toHaveLength(6);
    const site = panelOf(s, null, "site:s1")!;
    expect(site.kind).toBe("site");
    expect(site.tabs[1].items?.every((i) => i.uid.startsWith("dev:s1"))).toBe(true);
  });

  it("is absent without a selection", () => {
    expect(panelOf(s, null, null)).toBeNull();
  });
});

describe("the panel action", () => {
  const s = scene();

  it("flies a device to its block and an area to itself", () => {
    expect(panelOf(s, "dev:s0d1", null)?.topology).toBe("block:s0:campus");
    expect(panelOf(s, null, "block:s0:campus")?.topology).toBe("block:s0:campus");
    expect(panelOf(s, null, "block:s0:campus")?.icon).toBe("campus");
    expect(panelOf(s, null, "site:s1")?.icon).toBe("site");
  });

  it("opens the 2D diagram of the site, or the Fabric of a metro", () => {
    expect(panelOf(s, "dev:s0d1", null)?.diagram).toBe("s0");
    expect(panelOf(s, null, "block:s0:campus")?.diagram).toBe("s0");
    expect(panelOf(s, null, "site:s1")?.diagram).toBe("s1");
    expect(diagramOf(s, "eqx:fabric:SP")).toBe("fabric/SP");
    expect(diagramOf(s, "eqx:fabric:unknown")).toBeNull();
  });

  it("names a device with its role once when the tier says the same, and counts its tunnels", () => {
    const t = estate({ sites: 2, devices: 2, ports: 0 });
    t.render_t1 = t.render_t1.map((row) => (row.uid === "dev:s0d0" ? { ...row, role: "sdwan-hub", tier: "sdwan-hub", n_tunnels: 7 } : row));
    const r = createNullRenderer();
    r.setTier("layout", base(t));
    for (const name of ["render_t0", "render_t1", "render_t1_edges"] as TableName[]) r.setTier(name, t[name]);
    const panel = panelOf(r.scene, "dev:s0d0", null)!;
    expect(panel.subtitle).toBe("sdwan-hub");
    expect(panel.tabs[0].facts).toContainEqual(["Tunnels", "7"]);
  });
});

describe("the Fabric ports tab", () => {
  it("lists the Fabric ports of an Equinix device and the Fabric ports bound to the device", () => {
    const t = estate({ sites: 1, devices: 2, ports: 2 });
    const r = createNullRenderer();
    r.setTier("layout", base(t));
    for (const name of ["render_t0", "render_t1", "render_t1_edges"] as TableName[]) r.setTier(name, t[name]);
    r.setTier("render_t1_fabric_ports", [
      {
        uid: "eqx:port:1", device_uid: "dev:s0d0", name: "PORT-XA2-PRI-01", ibx: "XA2", metro: "XA", state: "ACTIVE",
        speed_mbps: 100000, redundancy: "primary", lag_name: "ae1", cable_ids: "10000001", bound_by: "name+cable",
        port_uid: "dev:s0d1/port/eth1-3", port_device: "dev:s0d1", binding_issue: null, binding_ports: null,
      },
      {
        uid: "eqx:port:2", device_uid: "dev:s0d0", name: "PORT-XA2-SEC-01", ibx: "XA2", metro: "XA", state: "ACTIVE",
        speed_mbps: 10000, redundancy: "secondary", lag_name: null, cable_ids: null, bound_by: null, port_uid: null,
        port_device: null, binding_issue: "several-ports", binding_ports: "dev:s0d1/port/eth1-4, dev:s0d1/port/eth1-5",
      },
    ]);
    const fabric = (uid: string) => panelOf(r.scene, uid, null)!.tabs.find((tab) => tab.name === "Fabric ports")?.items;
    expect(fabric("dev:s0d0")).toEqual([
      {
        uid: "eqx:port:1",
        label: "PORT-XA2-PRI-01",
        meta: "XA2, ACTIVE, 100 Gbps, primary, LAG ae1, cable 10000001, to s0d1 eth1-3, bound by name+cable",
        target: "dev:s0d1",
      },
      {
        uid: "eqx:port:2",
        label: "PORT-XA2-SEC-01",
        meta: "XA2, ACTIVE, 10 Gbps, secondary, not bound: several-ports (dev:s0d1/port/eth1-4, dev:s0d1/port/eth1-5)",
      },
    ]);
    expect(fabric("dev:s0d1")).toEqual([
      {
        uid: "eqx:port:1",
        label: "PORT-XA2-PRI-01",
        meta: "XA2, ACTIVE, 100 Gbps, primary, LAG ae1, cable 10000001, on eth1-3, bound by name+cable",
        target: "dev:s0d0",
      },
    ]);
  });
});
