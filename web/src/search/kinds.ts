/** The names the search shows for its kinds and its side-store tables, the
 *  legacy labels each kind stands for, and the one-line text of a hit. */

import { KINDS, type Kind, type SearchHit } from "./types";

const NAMES: Record<Kind, [one: string, many: string]> = {
  device: ["Device", "Devices"],
  interface: ["Interface", "Interfaces"],
  site: ["Site", "Sites"],
  prefix: ["Prefix", "Prefixes"],
  ip_address: ["IP address", "IP addresses"],
  endpoint: ["Endpoint", "Endpoints"],
  vrf: ["VRF", "VRFs"],
  segment: ["Segment", "Segments"],
  application: ["Application", "Applications"],
  arp: ["ARP entry", "ARP entries"],
  mac: ["MAC table entry", "MAC table entries"],
  route: ["Route", "Routes"],
  ospf_lsa: ["OSPF LSA", "OSPF LSAs"],
};

export function isKind(value: string): value is Kind {
  return (KINDS as readonly string[]).includes(value);
}

function capital(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** "Devices"; a kind the search does not know as it came. */
export function kindPlural(kind: string): string {
  return isKind(kind) ? NAMES[kind][1] : capital(kind);
}

/** "Device"; a kind the search does not know as it came. */
export function kindSingular(kind: string): string {
  return isKind(kind) ? NAMES[kind][0] : capital(kind);
}

export function kindPluralLower(kind: string): string {
  const name = kindPlural(kind);
  return /^[A-Z][A-Z]/.test(name) ? name : name.charAt(0).toLowerCase() + name.slice(1);
}

/** The graph label of a legacy hit, by the kind it stands for. */
const LEGACY: Record<string, Kind> = {
  Device: "device",
  Interface: "interface",
  Site: "site",
  Prefix: "prefix",
  IpAddress: "ip_address",
  Endpoint: "endpoint",
  VrfInstance: "vrf",
  BridgeDomain: "segment",
  BusinessService: "application",
};

/** The kind a legacy label stands for; an unknown label stays the label. */
export function kindOfLabel(label: string | null): string {
  if (!label) return "object";
  return LEGACY[label] ?? label;
}

/** The side-store table a hit was read from; null for any other hit. */
export function sourceTable(source: SearchHit["source"]): string | null {
  switch (source) {
    case "arp":
      return "ARP table";
    case "mac":
      return "MAC table";
    case "rib":
      return "RIB";
    case "ospf_lsdb":
      return "OSPF LSDB";
    default:
      return null;
  }
}

/** "3", or "10000+" for a count the server stopped at. */
export function countText(count: number, exact: boolean): string {
  return exact ? String(count) : `${count}+`;
}

function field(hit: SearchHit, name: string): string {
  const value = hit.fields[name];
  return value === null || value === undefined ? "" : String(value);
}

const join = (...parts: string[]) => parts.filter(Boolean).join(" ");

/** A side-store row in one line, e.g. "10.1.2.7 at aa:bb:cc:dd:ee:ff on edge1
 *  Gi0/1, VLAN 20"; null for a graph or local hit, or a row with no fields. */
export function rowText(hit: SearchHit): string | null {
  if (!sourceTable(hit.source)) return null;
  const device = field(hit, "device") || field(hit, "device_uid");
  const on = device ? `on ${join(device, field(hit, "interface"))}` : "";
  const vlan = field(hit, "vlan") ? `VLAN ${field(hit, "vlan")}` : "";
  const vrf = field(hit, "vrf") ? `VRF ${field(hit, "vrf")}` : "";
  let head = "";
  const tail: string[] = [];
  switch (hit.source) {
    case "arp":
      head = join(field(hit, "ip"), field(hit, "mac") ? `at ${field(hit, "mac")}` : "", on);
      tail.push(vlan, vrf);
      break;
    case "mac":
      head = join(field(hit, "mac"), on);
      tail.push(vlan);
      break;
    case "rib": {
      const via = join(field(hit, "next_hop"), device ? "" : field(hit, "interface"));
      head = join(field(hit, "prefix"), via ? `via ${via}` : "", on);
      tail.push(vrf, field(hit, "protocol"));
      break;
    }
    case "ospf_lsdb":
      head = join(
        field(hit, "lsa_type"),
        field(hit, "lsid"),
        field(hit, "adv_router") ? `from ${field(hit, "adv_router")}` : "",
        on,
      );
      tail.push(field(hit, "area") ? `area ${field(hit, "area")}` : "", vrf);
      break;
  }
  const text = [head, ...tail].filter(Boolean).join(", ");
  return text || null;
}

/** The text a hit shows: its name (or its row), and a second line. */
export function hitText(hit: SearchHit): { name: string; detail: string; uid: string | null } {
  const table = sourceTable(hit.source);
  if (table) {
    return { name: rowText(hit) ?? (hit.name || hit.key), detail: [table, hit.detail].filter(Boolean).join(", "), uid: null };
  }
  return { name: hit.name || hit.uid || hit.key, detail: hit.detail, uid: hit.uid };
}
