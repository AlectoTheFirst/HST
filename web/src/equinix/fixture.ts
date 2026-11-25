/** A made-up metro for the Equinix pane tests: 2 IBX, 3 Fabric ports, 2
 *  switches, 1 Network Edge device, and circuits to a cloud, to another
 *  metro, to another party, between 2 ports of the account, and from the Network Edge
 *  device. */

import type { EquinixEnd, EquinixMetroView } from "../api/types";

const port = (node: string, name: string, ibx: string, tag: number | null, metro = "XX"): EquinixEnd => ({
  kind: "port",
  node,
  name,
  ibx,
  metro,
  device: null,
  device_name: null,
  tag,
});

const QUERIES = [
  { key: "equinix-fabric-ports", title: "Fabric ports", description: "every Fabric port of a metro" },
  { key: "equinix-circuits", title: "Circuits", description: "the circuits with an end in a metro that are not ended" },
];

export const METROS = {
  metros: [
    { metro: "XX", ports: 3, ibxs: ["XX1", "XX2"], edge_devices: 1 },
    { metro: "YY", ports: 1, ibxs: ["YY1"], edge_devices: 0 },
  ],
  queries: QUERIES,
};

export const METRO: EquinixMetroView = {
  metro: "XX",
  ports: [
    {
      uid: "eqx:port:pri",
      name: "ACME-XX1-EXT-PRI-01",
      ibx: "XX1",
      state: "ACTIVE",
      speed_mbps: 10000,
      redundancy: "primary",
      lag: "ae9",
      cable_ids: ["21000001"],
      bound: { device: "dev:xx-swc-02", port: "dev:xx-swc-02/port/eth1-3", port_name: "Ethernet1/3", by: "name+cable" },
    },
    {
      uid: "eqx:port:sec",
      name: "ACME-XX1-EXT-SEC-01",
      ibx: "XX1",
      state: "ACTIVE",
      speed_mbps: 10000,
      redundancy: "secondary",
      lag: null,
      cable_ids: ["21000002"],
      bound: { device: "dev:xx-swc-02", port: "dev:xx-swc-02/port/eth1-4", port_name: "Ethernet1/4", by: "operator" },
    },
    {
      uid: "eqx:port:int",
      name: "ACME-XX2-INT-PRI-01",
      ibx: "XX2",
      state: "ACTIVE",
      speed_mbps: 100000,
      redundancy: "primary",
      lag: null,
      cable_ids: ["21000003"],
      bound: null,
    },
  ],
  devices: [{ uid: "dev:xx-swc-02", name: "XX-SWC-02", platform: "nxos", kind: "switch" }],
  edge_devices: [
    {
      uid: "eqx:device:edge",
      name: "XX-EDGE-01",
      vendor: "Cisco",
      model: "C8000V",
      role: "router",
      ibx: "XX1",
      status: "PROVISIONED",
      bound_device: null,
      same_as: null,
      same_as_name: null,
    },
  ],
  circuits: [
    {
      uid: "vc:cloud-1",
      name: "XX_CLOUD_100",
      type: "EVPL_VC",
      state: "ACTIVE",
      bandwidth_mbps: 1000,
      cabled: false,
      a: port("eqx:port:pri", "ACME-XX1-EXT-PRI-01", "XX1", 100),
      z: { kind: "provider", name: "AWS Direct Connect", tag: null },
    },
    {
      uid: "vc:cloud-2",
      name: "XX_CLOUD_101",
      type: "EVPL_VC",
      state: "ACTIVE",
      bandwidth_mbps: 1000,
      cabled: false,
      a: port("eqx:port:pri", "ACME-XX1-EXT-PRI-01", "XX1", 101),
      z: { kind: "provider", name: "AWS Direct Connect", tag: null },
    },
    {
      uid: "vc:yy",
      name: "XX_YY_200",
      type: "EVPL_VC",
      state: "ACTIVE",
      bandwidth_mbps: 500,
      cabled: true,
      a: port("eqx:port:sec", "ACME-XX1-EXT-SEC-01", "XX1", 200),
      z: port("eqx:port:yy", "ACME-YY1-EXT-PRI-01", "YY1", 200, "YY"),
    },
    {
      uid: "vc:partner",
      name: "PARTNER_300",
      type: "EVPL_VC",
      state: "ACTIVE",
      bandwidth_mbps: 100,
      cabled: false,
      a: { kind: "other", name: "PARTNER-FW-NODE0", tag: null },
      z: port("eqx:port:sec", "ACME-XX1-EXT-SEC-01", "XX1", 300),
    },
    {
      uid: "vc:internal",
      name: "XX1_XX2_400",
      type: "EVPL_VC",
      state: "ACTIVE",
      bandwidth_mbps: 1000,
      cabled: false,
      a: port("eqx:port:sec", "ACME-XX1-EXT-SEC-01", "XX1", 400),
      z: port("eqx:port:int", "ACME-XX2-INT-PRI-01", "XX2", 400),
    },
    {
      uid: "vc:edge",
      name: "XX_EDGE_500",
      type: "EVPL_VC",
      state: "ACTIVE",
      bandwidth_mbps: 1000,
      cabled: false,
      a: {
        kind: "edge",
        node: "eqx:device:edge/if/gi6",
        name: "GigabitEthernet6",
        ibx: "XX1",
        metro: "XX",
        device: "eqx:device:edge",
        device_name: "XX-EDGE-01",
        tag: null,
      },
      z: port("eqx:port:int", "ACME-XX2-INT-PRI-01", "XX2", 500),
    },
  ],
  ended_circuits: 4,
  queries: QUERIES,
};
