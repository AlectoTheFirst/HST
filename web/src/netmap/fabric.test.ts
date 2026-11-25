import { describe, expect, it } from "vitest";
import { METRO } from "../equinix/fixture";
import { fabricModel, isFabric, metroOf } from "./fabric";
import { toElkGraph, toFlatElkGraph } from "./layout";

describe("fabricModel", () => {
  const { model, circuits } = fabricModel(METRO);
  const node = (id: string) => model.nodes.find((n) => n.id === id)!;
  const cable = (from: string, to: string) => model.cables.find((c) => c.from.dev === from && c.to.dev === to)!;

  it("draws the own devices, one block per IBX and the far ends in one site", () => {
    expect(node("fabric:XX")).toMatchObject({ kind: "site", label: "Equinix Fabric XX" });
    expect(model.nodes.filter((n) => n.kind === "block").map((n) => n.label)).toEqual([
      "Own devices",
      "IBX XX1",
      "IBX XX2",
      "Far ends",
    ]);
    expect(node("dev:xx-swc-02")).toMatchObject({ kind: "device", parent: "fabric:XX:ours", role: "switch" });
    expect(node("eqx:device:edge")).toMatchObject({ parent: "fabric:XX:ours", role: "router", vendor: "Cisco" });
    expect(node("eqx:port:pri")).toMatchObject({ parent: "fabric:XX:ibx:XX1", vendor: "Equinix" });
    expect(node("eqx:port:int").parent).toBe("fabric:XX:ibx:XX2");
    expect(node("far:provider:AWS Direct Connect")).toMatchObject({ parent: "fabric:XX:far", role: "cloud" });
  });

  it("runs a cable from a switch port to the Fabric port it realizes", () => {
    expect(cable("dev:xx-swc-02", "eqx:port:pri")).toMatchObject({
      from: { port: "Ethernet1/3" },
      source: "bound by name+cable",
      speed_mbps: 10000,
      lateral: false,
    });
  });

  it("draws the circuits between two nodes as one line that lists them", () => {
    const aws = cable("eqx:port:pri", "far:provider:AWS Direct Connect");
    expect(aws).toMatchObject({ to: { port: "2 circuits" }, speed_mbps: 2000, lateral: false });
    expect(circuits.get(aws.id)).toEqual([
      "XX_CLOUD_100: EVPL_VC, 1000 Mbit/s, ACTIVE, VLAN 100 / none",
      "XX_CLOUD_101: EVPL_VC, 1000 Mbit/s, ACTIVE, VLAN 101 / none",
    ]);
  });

  it("lays a circuit between two Fabric ports of the metro along one row", () => {
    const internal = model.cables.find((c) => circuits.get(c.id)?.some((t) => t.startsWith("XX1_XX2_400")))!;
    expect(internal.lateral).toBe(true);
  });

  it("gives every device a place in both layouts", () => {
    const devices = model.nodes.filter((n) => n.kind === "device").map((n) => n.id);
    expect(toFlatElkGraph(model).children!.map((c) => c.id)).toEqual(expect.arrayContaining(devices));
    const nested = JSON.stringify(toElkGraph(model));
    for (const id of devices) expect(nested).toContain(JSON.stringify(id));
  });
});

describe("the Fabric scope", () => {
  it("names a metro", () => {
    expect(isFabric("fabric/SP")).toBe(true);
    expect(isFabric("FR2")).toBe(false);
    expect(metroOf("fabric/SP")).toBe("SP");
  });
});
