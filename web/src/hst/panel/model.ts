import { regionName, type Scene } from "../render/scene";
import type { Row } from "../render/types";

/** One entry of a panel list: an element the panel can fly to. */
export interface Item {
  uid: string;
  label: string;
  meta: string;
  /** The element the item flies to, when it is not `uid`. */
  target?: string;
}

export interface Tab {
  name: string;
  facts?: [string, string][];
  items?: Item[];
}

export interface Panel {
  uid: string;
  kind: "device" | "block" | "site" | "tunnel" | "circuit";
  title: string;
  subtitle: string;
  /** The icon key: a block kind, `site`, or `device`. */
  icon: string;
  /** The element "View topology" flies to: the device's block, or the area itself. */
  topology: string | null;
  /** The workspace map scope "View topology" opens in the workspace: the 2D diagram of the site, or
   *  `fabric/<metro>` for the Equinix Fabric of a metro; null for a cloud or the unassigned devices. */
  diagram: string | null;
  tabs: Tab[];
}

const FABRIC_METRO = "eqx:fabric:";
const SPINE_SITE = "site:EQUINIX-FABRIC-";

/** The 2D drawing of `uid` (netmap/NetworkMapPage.tsx `siteOfScope`). The Fabric, the clouds and the unassigned
 *  devices are sites of this map only (hst/map/layout.py, hst/map/tiers/fabric.py); a metro's Fabric device
 *  and a spine site open the Fabric of the metro. */
export function diagramOf(scene: Scene, uid: string): string | null {
  if (uid.startsWith(FABRIC_METRO)) {
    const metro = uid.slice(FABRIC_METRO.length);
    return metro && metro !== "unknown" ? `fabric/${metro}` : null;
  }
  const site = uid.startsWith("site:") ? uid : scene.siteOf(uid);
  if (!site) return null;
  if (site.startsWith(SPINE_SITE)) return `fabric/${site.slice(SPINE_SITE.length)}`;
  const code = site.slice("site:".length);
  return code === "unassigned" || code === "EQUINIX-FABRIC" || code.startsWith("CLOUD-") ? null : code;
}

function n(row: Row | undefined, column: string): number {
  return Number(row?.[column] ?? 0);
}

function text(value: unknown): string {
  return value === null || value === undefined || value === "" ? "unknown" : String(value);
}

function labelOf(scene: Scene, uid: string): string {
  return String(scene.row("render_t1", uid)?.label ?? scene.row("render_t0", uid)?.label ?? uid.replace(/^(site|block):/, ""));
}

function devicePanel(scene: Scene, uid: string): Panel {
  const row = scene.row("render_t1", uid);
  const site = scene.siteOf(uid);
  const block = scene.blockOf(uid);
  const links: Item[] = [];
  for (const e of scene.rows("render_t1_edges")) {
    const other = e.a_uid === uid ? String(e.b_uid) : e.b_uid === uid ? String(e.a_uid) : null;
    if (!other) continue;
    const parts = [
      n(e, "cable_count") ? `${n(e, "cable_count")} cables` : "",
      n(e, "lag_count") ? `${n(e, "lag_count")} LAGs` : "",
      n(e, "tunnel_count") ? `${n(e, "tunnel_count")} tunnels` : "",
    ].filter(Boolean);
    links.push({ uid: other, label: labelOf(scene, other), meta: parts.join(", ") });
  }
  links.sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  return {
    uid,
    kind: "device",
    icon: "device",
    topology: block,
    diagram: diagramOf(scene, uid),
    title: labelOf(scene, uid),
    subtitle: [...new Set([row?.role, row?.tier].filter((x) => x).map(String))].join(", ") || "device",
    tabs: [
      {
        name: "Overview",
        facts: [
          ["Model", [row?.vendor, row?.model].filter((x) => x).map(String).join(" ") || "unknown"],
          ["Software", text(row?.os_version)],
          ["IP address", text(row?.mgmt_ip)],
          ["Site", site ? labelOf(scene, site) : "unassigned"],
          ["Status", text(row?.status)],
          ["Tunnels", String(n(row, "n_tunnels"))],
        ],
      },
      portsTab(scene, uid),
      segmentsTab(scene, uid),
      { name: "Links", items: links },
      ...fabricTab(scene, uid),
      ...circuitsTab(scene, uid),
    ],
  };
}

/** The segments of a device with clients, one item per segment; the item opens the client list. */
function segmentsTab(scene: Scene, uid: string): Tab {
  const items: Item[] = scene.segmentsOf(uid).map((s) => ({
    uid: String(s.uid),
    label: String(s.prefix ?? (s.vid !== null && s.vid !== undefined ? `VLAN ${s.vid}` : (s.name ?? "no VLAN"))),
    meta: [s.name && s.prefix ? String(s.name) : "", `${n(s, "client_count")} clients`].filter(Boolean).join(", "),
  }));
  if (items.length === 0) return { name: "Segments", facts: [["Segments", "none with clients at this run"]] };
  return { name: "Segments", items };
}

/** The port groups of a device, one item per group with its state counts; the first port of the group is the fly-to. */
function portsTab(scene: Scene, uid: string): Tab {
  const byName = new Map<string, string>();
  for (const p of scene.rows("render_t2_ports")) if (p.device_uid === uid) byName.set(String(p.name), String(p.uid));
  const items: Item[] = [];
  for (const g of scene.rows("render_t2_port_groups")) {
    if (g.device_uid !== uid) continue;
    const range = g.first_name === g.last_name ? String(g.first_name) : `${g.first_name} to ${g.last_name}`;
    const states = [
      ["up", g.up],
      ["down", g.down],
      ["admin down", g.admin_down],
    ]
      .filter(([, count]) => Number(count) > 0)
      .map(([k, count]) => `${count} ${k}`);
    items.push({
      uid: byName.get(String(g.first_name)) ?? uid,
      label: range,
      meta: `${n(g, "port_count")} ports${states.length ? `: ${states.join(", ")}` : ""}`,
    });
  }
  if (items.length === 0) return { name: "Ports", facts: [["Ports", "not loaded"]] };
  return { name: "Ports", items };
}

function areaPanel(scene: Scene, uid: string, kind: "block" | "site"): Panel {
  const row = scene.row("render_t0", uid);
  const devices: Item[] = [];
  for (const p of scene.layout.values()) {
    if (p.kind !== "device") continue;
    if ((kind === "block" ? scene.blockOf(p.uid) : scene.siteOf(p.uid)) !== uid) continue;
    const d = scene.row("render_t1", p.uid);
    devices.push({ uid: p.uid, label: labelOf(scene, p.uid), meta: [d?.role, d?.status].filter((x) => x).map(String).join(", ") });
  }
  devices.sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  return {
    uid,
    kind,
    icon: kind === "block" ? text(row?.block_kind) : "site",
    topology: uid,
    diagram: diagramOf(scene, uid),
    title: labelOf(scene, uid),
    subtitle: kind === "block" ? `${text(row?.block_kind)} block` : "site",
    tabs: [
      {
        name: "Overview",
        facts: [
          ["Devices", String(n(row, "device_count"))],
          ["Observed", String(n(row, "observed_count"))],
          ["Carried", String(n(row, "carried_count"))],
          ["Failed", String(n(row, "failed_count"))],
          ["Changed since the previous run", String(n(row, "added_count") + n(row, "removed_count") + n(row, "changed_count"))],
        ],
      },
      { name: "Devices", items: devices },
    ],
  };
}

/** One circuit as a panel item from the side of `own`: its name, the far end and its facts. */
function circuitItem(scene: Scene, c: Row, own: string | null): Item {
  const far = String(own !== null && String(c.a_device) === own ? c.z_device : c.a_device);
  const vlans = [c.a_vlan, c.z_vlan].filter((v) => v !== null && v !== undefined).map(String);
  const meta = [
    own !== null ? `to ${labelOf(scene, far)}` : "",
    text(c.type),
    c.bandwidth_mbps ? `${n(c, "bandwidth_mbps")} Mbps` : "",
    text(c.state),
    vlans.length ? `VLAN ${vlans.join(" / ")}` : "",
    c.family ? String(c.family) : c.provider ? String(c.provider) : "",
  ].filter(Boolean);
  return { uid: String(c.uid), label: String(c.name ?? c.uid), meta: meta.join(", "), target: far };
}

/** The Equinix Fabric circuits of a device, as a tab when it has any. */
function circuitsTab(scene: Scene, uid: string): Tab[] {
  const items = [...scene.rows("render_t1_circuits")]
    .filter((c) => c.a_device === uid || c.z_device === uid)
    .map((c) => circuitItem(scene, c, uid))
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  return items.length > 0 ? [{ name: "Circuits", items }] : [];
}

/** The Fabric ports of an Equinix device, or the Fabric ports bound to the ports of a device, as a tab when it has
 *  any. */
function fabricTab(scene: Scene, uid: string): Tab[] {
  const portName = (port: string) => String(scene.row("render_t2_ports", port)?.name ?? port.replace(/^.*\/port\//, ""));
  const items: Item[] = [...scene.rows("render_t1_fabric_ports")]
    .filter((p) => p.device_uid === uid || p.port_device === uid)
    .map((p) => {
      const own = p.device_uid === uid;
      const mbps = n(p, "speed_mbps");
      const binding = p.port_uid
        ? `${own ? `to ${labelOf(scene, String(p.port_device))} ` : "on "}${portName(String(p.port_uid))}, bound by ${text(p.bound_by)}`
        : `not bound${p.binding_issue ? `: ${p.binding_issue}` : ""}${p.binding_ports ? ` (${p.binding_ports})` : ""}`;
      const meta = [
        p.ibx ? String(p.ibx) : "",
        text(p.state),
        mbps ? (mbps >= 1000 ? `${mbps / 1000} Gbps` : `${mbps} Mbps`) : "",
        p.redundancy ? String(p.redundancy) : "",
        p.lag_name ? `LAG ${p.lag_name}` : "",
        p.cable_ids ? `cable ${p.cable_ids}` : "",
        binding,
      ].filter(Boolean);
      const far = own ? p.port_device : p.device_uid;
      return { uid: String(p.uid), label: String(p.name ?? p.uid), meta: meta.join(", "), ...(far ? { target: String(far) } : {}) };
    })
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  return items.length > 0 ? [{ name: "Fabric ports", items }] : [];
}

/** The circuits of a picked circuit line between two sites or two devices. */
function circuitPanel(scene: Scene, id: string): Panel | null {
  const detail = scene.circuitDetail(id);
  if (!detail) return null;
  const items = detail.circuits
    .map((c) => circuitItem(scene, c, null))
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  return {
    uid: id,
    kind: "circuit",
    icon: "wan-edge",
    topology: null,
    diagram: null,
    title: `${labelOf(scene, detail.from)} to ${labelOf(scene, detail.to)}`,
    subtitle: `${items.length} ${items.length === 1 ? "circuit" : "circuits"}`,
    tabs: [{ name: "Circuits", items }],
  };
}

/** The far ends of a chosen tunnel line: an arc, a spoke, a bundle, or the own block of a hub. */
function tunnelPanel(scene: Scene, id: string): Panel | null {
  const detail = scene.tunnelDetail(id);
  if (!detail) return null;
  const items: Item[] = detail.ends
    .map((e) => ({ uid: e.uid, label: labelOf(scene, e.uid), meta: `${e.tunnels} tunnels` }))
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));
  const total = detail.ends.reduce((sum, e) => sum + e.tunnels, 0);
  const to = detail.title.startsWith("region:") ? regionName(detail.title) : labelOf(scene, detail.title);
  return {
    uid: id,
    kind: "tunnel",
    icon: "wan-edge",
    topology: null,
    diagram: null,
    title: `${labelOf(scene, detail.from)} to ${to}`,
    subtitle: `${items.length} far ${items.length === 1 ? "end" : "ends"}, ${total} tunnels`,
    tabs: [{ name: "Far ends", items }],
  };
}

/** The panel of the chosen tunnel line, else of the selected device, else of the selected site or block; null
 *  without a selection. */
export function panelOf(scene: Scene, selected: string | null, area: string | null, tunnel: string | null = null): Panel | null {
  const line = tunnel ? (tunnel.startsWith("circuit:") ? circuitPanel(scene, tunnel) : tunnelPanel(scene, tunnel)) : null;
  if (line) return line;
  if (selected && scene.layout.get(selected)?.kind === "device") return devicePanel(scene, selected);
  if (!area) return null;
  const kind = scene.layout.get(area)?.kind;
  if (kind === "block") return areaPanel(scene, area, "block");
  if (kind === "site") return areaPanel(scene, area, "site");
  return null;
}
