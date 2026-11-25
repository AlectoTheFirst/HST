// @vitest-environment node
import { describe, it, expect } from "vitest";
import { STRATA_LAYERS, FALLBACK_LAYER, layerOf, LAYER_BY_KIND, SYNTHETIC_KINDS } from "./layers";

// @ts-expect-error -- "fs" has no type declarations in scope here
import { readFileSync } from "fs";
// @ts-expect-error -- "url" has no type declarations in scope here
import { fileURLToPath } from "url";

const LABELS_PY_PATH = fileURLToPath(new URL("../../../../src/hst/core/labels.py", import.meta.url));

function labelsPyKeys(): string[] {
  const text = readFileSync(LABELS_PY_PATH, "utf-8");
  const keys: string[] = [];
  for (const line of text.split("\n")) {
    // LABELS keys are alphanumeric, with digits (L2Vni, L3Domain, L3Out).
    const match = line.match(/^\s+"([A-Za-z0-9]+)":\s*LabelSpec/);
    if (match) keys.push(match[1]);
  }
  return keys;
}

function labelsPyTiers(): Record<string, number> {
  const text = readFileSync(LABELS_PY_PATH, "utf-8");
  const start = text.indexOf("TIER_BY_KIND: dict[str, int] = {");
  if (start === -1) throw new Error("TIER_BY_KIND block not found in labels.py");
  const end = text.indexOf("\n}", start);
  const body = text.slice(start, end);
  const tiers: Record<string, number> = {};
  for (const line of body.split("\n")) {
    const match = line.match(/^\s+"([A-Za-z0-9]+)":\s*(\d+),/);
    if (match) tiers[match[1]] = Number(match[2]);
  }
  return tiers;
}

const REPRESENTATIVE_KINDS = [
  // §1 physical
  "Site",
  "Device",
  "Port",
  // §2 L2
  "Interface",
  "VlanInstance",
  "BridgeDomain",
  "Ssid",
  "Endpoint",
  // §3 L3/routing
  "VrfInstance",
  "RoutingDomain",
  "Prefix",
  "IpAddress",
  "RoutePolicy",
  // §4 overlay/transport
  "Tunnel",
  "WanLink",
  "SdwanBusinessPolicy",
  // §5 ACI policy
  "Contract",
  "VzAny",
  "PbrPolicy",
  // §6 firewall
  "FwRulebase",
  "NatRule",
  "Zone",
  "NetObject",
  "SvcObject",
  // §7 LB/DNS
  "VirtualService",
  // §8 Zscaler
  "ZpaAccessRule",
  // §9 AWS
  "Vpc",
  "NatGw",
  // §10 Azure
  "AzFirewall",
  // §12 virtualization/compute/app
  "Server",
  "AppComponent",
] as const;

describe("STRATA_LAYERS", () => {
  it("is bottom-up physical, routing, policy, application", () => {
    expect(STRATA_LAYERS).toEqual(["physical", "routing", "policy", "application"]);
  });

  it("has 4 tiers, indices 0..3", () => {
    expect(STRATA_LAYERS).toHaveLength(4);
  });
});

describe("layerOf over a kind sample", () => {
  it("maps each sample kind to a valid layer index", () => {
    for (const kind of REPRESENTATIVE_KINDS) {
      const layer = layerOf(kind);
      expect(layer).toBeGreaterThanOrEqual(0);
      expect(layer).toBeLessThan(STRATA_LAYERS.length);
    }
  });

  it("gives the same index for the same kind twice", () => {
    for (const kind of REPRESENTATIVE_KINDS) {
      expect(layerOf(kind)).toBe(layerOf(kind));
    }
  });

  it("falls back to the physical tier for an unrecognized kind", () => {
    expect(layerOf("SomeFutureVendorKind")).toBe(FALLBACK_LAYER);
    expect(FALLBACK_LAYER).toBe(0);
  });
});

describe("layerOf tiers", () => {
  it("physical: devices, interfaces, ports, WAN links, L2, sites", () => {
    for (const kind of ["Site", "Device", "Interface", "Port", "WanLink", "VlanInstance", "BridgeDomain", "Ssid"]) {
      expect(layerOf(kind)).toBe(0);
    }
  });

  it("routing: prefixes, IP addresses, VRFs, L3/routing domains, route policies, tunnels", () => {
    for (const kind of ["Prefix", "IpAddress", "VrfInstance", "RoutingDomain", "RoutePolicy", "Tunnel"]) {
      expect(layerOf(kind)).toBe(1);
    }
  });

  it("policy: firewall rulebases and rules, NAT, contracts, VzAny, ZPA access rules, Azure firewalls, PBR and SD-WAN business policies, zones", () => {
    for (const kind of [
      "FwRulebase",
      "FwRule",
      "NatRule",
      "Contract",
      "VzAny",
      "ZpaAccessRule",
      "AzFirewall",
      "PbrPolicy",
      "SdwanBusinessPolicy",
      "Zone",
    ]) {
      expect(layerOf(kind)).toBe(2);
    }
  });

  it("application: endpoints, virtual services, service and net objects", () => {
    for (const kind of ["Endpoint", "VirtualService", "NetObject", "SvcObject"]) {
      expect(layerOf(kind)).toBe(3);
    }
  });
});

describe("LAYER_BY_KIND against core/labels.py LABELS", () => {
  const pyKeys = labelsPyKeys();
  it("finds LABELS keys in labels.py", () => {
    expect(pyKeys.length).toBeGreaterThan(50);
  });

  it("every labels.py LABELS key has an explicit LAYER_BY_KIND entry", () => {
    const missing = pyKeys.filter((key) => !(key in LAYER_BY_KIND));
    expect(missing).toEqual([]);
  });

  it("every LAYER_BY_KIND key is a labels.py key or a declared synthetic kind", () => {
    const pyKeySet = new Set(pyKeys);
    const unexplained = Object.keys(LAYER_BY_KIND).filter(
      (key) => !pyKeySet.has(key) && !SYNTHETIC_KINDS.has(key),
    );
    expect(unexplained).toEqual([]);
  });
});

describe("TIER_BY_KIND in core/labels.py", () => {
  const pyTiers = labelsPyTiers();

  it("finds TIER_BY_KIND entries in labels.py", () => {
    expect(Object.keys(pyTiers).length).toBeGreaterThan(50);
  });

  it("every parsed labels.py tier value matches LAYER_BY_KIND", () => {
    const mismatches = Object.entries(pyTiers).filter(([k, v]) => LAYER_BY_KIND[k] !== v);
    expect(mismatches).toEqual([]);
  });

  it("every labels.py TIER_BY_KIND key is also a LAYER_BY_KIND key", () => {
    const missing = Object.keys(pyTiers).filter((key) => !(key in LAYER_BY_KIND));
    expect(missing).toEqual([]);
  });
});
