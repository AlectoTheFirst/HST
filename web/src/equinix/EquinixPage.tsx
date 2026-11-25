import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type { EquinixCircuit, EquinixEnd, EquinixMetroView, EquinixMetrosResponse, EquinixQuery, EquinixPort } from "../api/types";
import { useCanvas, type Point } from "../diagram/useCanvas";
import { chipPath, control } from "../diagram/diagram";
import { useWorkspace } from "../workspace/WorkspaceContext";
import { layoutMetro, type EquinixBundle, type EquinixNode } from "./layout";
import { rovingKeys, rovingTabIndex } from "../shell/rovingKeys";
import "../diagram/netmap.css";
import "../diagram/diagram.css";
import "./equinix.css";

type Mode = "fabric" | "queries";
type Panel = { kind: "node"; uid: string } | { kind: "cable"; index: number } | { kind: "bundle"; key: string };

function notActive(other: Record<string, number> | undefined) {
  const entries = Object.entries(other ?? {});
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  if (total === 0) return null;
  const title = entries.map(([state, n]) => `${state}: ${n}`).join(", ");
  return <span title={title}>{`, ${total} not active`}</span>;
}

export default function EquinixPage() {
  const [metro, setMetro] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("fabric");
  const [panel, setPanel] = useState<Panel | null>(null);

  const metros = useQuery({
    queryKey: ["equinix-metros"],
    queryFn: () => api<EquinixMetrosResponse>("/equinix/metros"),
  });
  const view = useQuery({
    queryKey: ["equinix-metro", metro],
    queryFn: () => api<EquinixMetroView>(`/equinix/metro?metro=${encodeURIComponent(metro!)}`),
    enabled: metro !== null,
  });

  const toolbar = (
    <div className="netmap-toolbar">
      <div className="segs netmap-layers" role="radiogroup" aria-label="Metro">
        {(metros.data?.metros ?? []).map((m, i) => (
          <button
            key={m.metro}
            type="button"
            role="radio"
            aria-checked={metro === m.metro}
            onKeyDown={rovingKeys("radio")}
            tabIndex={rovingTabIndex(metro === m.metro, i, metro !== null)}
            className={metro === m.metro ? "on" : ""}
            title={`${m.ports} Fabric ports, ${m.edge_devices} Network Edge devices`}
            onClick={() => {
              setMetro(m.metro);
              setPanel(null);
            }}
          >
            {m.metro}
          </button>
        ))}
      </div>
      <div className="segs netmap-layers" role="radiogroup" aria-label="Equinix view">
        {(
          [
            ["fabric", "Fabric"],
            ["queries", "Queries"],
          ] as [Mode, string][]
        ).map(([value, label], i) => (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={mode === value}
            onKeyDown={rovingKeys("radio")}
            tabIndex={rovingTabIndex(mode === value, i, true)}
            className={mode === value ? "on" : ""}
            onClick={() => setMode(value)}
          >
            {label}
          </button>
        ))}
      </div>
      {view.data && (
        <span className="equinix-summary">
          {view.data.ports.length} Fabric ports, {view.data.circuits.length} circuits
          {view.data.ended_circuits > 0 && `, ${view.data.ended_circuits} ended`}
          {notActive(view.data.other_circuits)}
        </span>
      )}
    </div>
  );

  let body;
  if (mode === "queries") {
    body = <QueryList queries={metros.data?.queries ?? []} metro={metro} />;
  } else if (metros.error) {
    body = <div className="netmap-empty">Metro list not loaded: {String(metros.error)}</div>;
  } else if (metro === null) {
    body = (
      <div className="netmap-empty">
        {metros.data
          ? metros.data.metros.length === 0
            ? "No Fabric port in the pinned run"
            : "No metro picked"
          : "Loading metros"}
      </div>
    );
  } else if (view.isLoading) {
    body = <div className="netmap-empty">Loading metro</div>;
  } else if (view.error) {
    body = (
      <div className="netmap-empty">
        {view.error instanceof ApiError && view.error.status === 404
          ? "Metro not in the pinned run"
          : `Metro not loaded: ${String(view.error)}`}
      </div>
    );
  } else if (view.data) {
    body = <Diagram data={view.data} panel={panel} setPanel={setPanel} />;
  }

  return (
    <div className="netmap">
      {toolbar}
      {body}
    </div>
  );
}

/** The state of a Fabric port that has no switch port. */
export function unboundText(port: EquinixPort): string {
  const u = port.unbound;
  const ports = (u?.ports ?? []).join(", ");
  switch (u?.reason) {
    case "binding-refused":
      return `${ports} (not in this run)`;
    case "cable-conflict":
      return `cable ID conflict on ${ports}`;
    case "several-ports":
      return `${u.ports.length} port descriptions (${ports})`;
    case "several-fabric-ports":
      return `another Fabric port in the description of ${ports}`;
    default:
      return "none";
  }
}

/** The shared chip style of a node kind. */
function chipRole(kind: string): string {
  if (kind === "switch" || kind === "edge") return "netmap-chip-device";
  if (kind === "metro" || kind === "provider" || kind === "other") return "netmap-chip-far";
  return "";
}

function linkPath(a: Point & { h: number }, b: Point & { h: number }): string {
  return chipPath(a, b);
}

/** Where the count of a bundle goes: the middle of its line. */
function labelAt(a: EquinixNode, b: EquinixNode): Point {
  if (Math.abs(a.y - b.y) < 1) return { x: (a.x + b.x) / 2, y: a.y - a.h / 2 - 38 };
  const [hi, lo] = a.y < b.y ? [a, b] : [b, a];
  return { x: (hi.x + lo.x) / 2, y: (hi.y + hi.h / 2 + lo.y - lo.h / 2) / 2 };
}

function endText(end: EquinixEnd | null): string {
  if (!end) return "not known";
  if (end.kind === "edge") return [end.device_name, end.name].filter(Boolean).join(" ");
  if (end.kind === "port") return [end.name, end.metro ? `(${end.metro})` : null].filter(Boolean).join(" ");
  return end.name ?? "not known";
}

function CircuitTable({ circuits }: { circuits: EquinixCircuit[] }) {
  return (
    <table className="equinix-circuits">
      <thead>
        <tr>
          <th>Circuit</th>
          <th>A</th>
          <th>Z</th>
          <th>Link</th>
        </tr>
      </thead>
      <tbody>
        {circuits.map((c) => (
          <tr key={c.uid}>
            <td>
              {c.name ?? c.uid}
              <div className="dim">
                {[c.type === "DEVICE_LINK" ? "device link" : c.type, c.bandwidth_mbps ? `${c.bandwidth_mbps} Mbit/s` : null]
                  .filter(Boolean)
                  .join(", ")}
              </div>
            </td>
            <td>
              {endText(c.a)}
              {c.a?.tag != null && <div className="dim">VLAN {c.a.tag}</div>}
            </td>
            <td>
              {endText(c.z)}
              {c.z?.tag != null && <div className="dim">VLAN {c.z.tag}</div>}
            </td>
            <td>{c.cabled ? "drawn" : "not drawn"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Diagram({
  data,
  panel,
  setPanel,
}: {
  data: EquinixMetroView;
  panel: Panel | null;
  setPanel: (p: Panel | null) => void;
}) {
  const layout = useMemo(() => layoutMetro(data), [data]);
  const { svg, viewBox, handlers } = useCanvas(layout.fit, {
    dragAttr: "data-drag",
    passthrough: "[data-cable], [data-node]",
  });
  const home = useMemo(() => new Map(layout.nodes.map((n) => [n.uid, n])), [layout]);

  // with a node picked, its cables and bundles stay lit and the rest fades
  const picked = panel?.kind === "node" ? panel.uid : null;
  const touches = (a: string, b: string) => picked === null || a === picked || b === picked;

  const node = picked ? home.get(picked) : undefined;
  const cable = panel?.kind === "cable" ? layout.cables[panel.index] : undefined;
  const bundle = panel?.kind === "bundle" ? layout.bundles.find((b) => b.key === panel.key) : undefined;
  const nodeBundles = (uid: string): EquinixBundle[] => layout.bundles.filter((b) => b.a === uid || b.b === uid);

  return (
    <>
      <svg
        ref={svg}
        className="netmap-canvas"
        viewBox={viewBox}
        role="group"
        aria-label="Equinix Fabric"
        {...handlers}
      >
        {layout.frames.map((f) => (
          <g key={`frame:${f.key}`} className="netmap-frame">
            <rect x={f.x} y={f.y} width={f.width} height={f.height} rx={10} />
            <text x={f.x + 12} y={f.y + 20}>
              {f.label}
            </text>
          </g>
        ))}
        {layout.bundles.map((b) => {
          const a = home.get(b.a);
          const z = home.get(b.b);
          if (!a || !z) return null;
          const on = panel?.kind === "bundle" && panel.key === b.key;
          const d = linkPath(a, z);
          const at = labelAt(a, z);
          return (
            <g
              key={b.key}
              className={"netmap-cable equinix-bundle" + (on ? " on" : "") + (touches(b.a, b.b) ? "" : " netmap-dim")}
              data-cable
              {...control(`${b.circuits.length} circuits: ${a.name} and ${z.name}`, () => setPanel(on ? null : { kind: "bundle", key: b.key }), on)}
            >
              <path className="netmap-cablehit" d={d} />
              <path d={d} style={{ strokeWidth: Math.min(1.5 + b.circuits.length * 0.5, 6) }}>
                <title>{`${b.circuits.length} circuits: ${a.name} and ${z.name}`}</title>
              </path>
              <text className="equinix-count" x={at.x} y={at.y}>
                {b.circuits.length}
              </text>
            </g>
          );
        })}
        {layout.cables.map((c, i) => {
          const a = home.get(c.device);
          const z = home.get(c.fabricPort);
          if (!a || !z) return null;
          const on = panel?.kind === "cable" && panel.index === i;
          const d = linkPath(a, z);
          return (
            <g
              key={`cable-${i}`}
              className={"netmap-cable" + (on ? " on" : "") + (touches(c.device, c.fabricPort) ? "" : " netmap-dim")}
              data-cable
              {...control(`Cable ${a.name} ${c.portName} to ${z.name}`, () => setPanel(on ? null : { kind: "cable", index: i }), on)}
            >
              <path className="netmap-cablehit" d={d} />
              <path d={d}>
                <title>{`${a.name} ${c.portName} to ${z.name}`}</title>
              </path>
            </g>
          );
        })}
        {layout.nodes.map((n) => {
          const on = picked === n.uid;
          return (
            <g
              key={n.uid}
              className={`netmap-node netmap-chip equinix-${n.kind} ${chipRole(n.kind)}` + (on ? " on" : "")}
              transform={`translate(${n.x} ${n.y})`}
              data-node={n.uid}
              {...control(`${n.name}`, () => setPanel(on ? null : { kind: "node", uid: n.uid }), on)}
            >
              <rect x={-n.w / 2} y={-n.h / 2} width={n.w} height={n.h} rx={7} />
              <text className="netmap-name" x={-n.w / 2 + 12} y={n.caption ? -2 : 4}>
                {n.name}
              </text>
              {n.caption && (
                <text className="netmap-caption" x={-n.w / 2 + 12} y={12}>
                  {n.caption}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      {layout.undrawn > 0 && !panel && (
        <div className="netmap-note">
          {layout.undrawn === 1 ? "1 circuit" : `${layout.undrawn} circuits`} not drawn
        </div>
      )}
      {cable && (
        <aside className="netmap-clients" aria-label="Cable details">
          <header>
            Cable
            <button type="button" onClick={() => setPanel(null)} aria-label="Close cable details">
              Close
            </button>
          </header>
          <dl className="netmap-linkends">
            <dt>Switch</dt>
            <dd>
              {home.get(cable.device)?.name ?? cable.device} <span className="netmap-port">{cable.portName || "not known"}</span>
            </dd>
            <dt>Fabric port</dt>
            <dd>{home.get(cable.fabricPort)?.name ?? cable.fabricPort}</dd>
            <dt>Bound by</dt>
            <dd>{cable.by === "operator" ? "the operator's port binding" : `the port description (${cable.by ?? "not known"})`}</dd>
          </dl>
        </aside>
      )}
      {bundle && (
        <aside className="netmap-clients equinix-panel" aria-label="Circuit details">
          <header>
            {bundle.circuits.length === 1 ? "1 circuit" : `${bundle.circuits.length} circuits`}
            <button type="button" onClick={() => setPanel(null)} aria-label="Close circuit details">
              Close
            </button>
          </header>
          <CircuitTable circuits={bundle.circuits} />
        </aside>
      )}
      {node && <NodePanel node={node} data={data} bundles={nodeBundles(node.uid)} onClose={() => setPanel(null)} />}
    </>
  );
}

function NodePanel({
  node,
  data,
  bundles,
  onClose,
}: {
  node: EquinixNode;
  data: EquinixMetroView;
  bundles: EquinixBundle[];
  onClose: () => void;
}) {
  const port = node.kind === "port" ? data.ports.find((p) => p.uid === node.uid) : undefined;
  const edge = node.kind === "edge" ? data.edge_devices.find((d) => d.uid === node.uid) : undefined;
  const switchPorts = node.kind === "switch" ? data.ports.filter((p) => p.bound?.device === node.uid) : [];
  const circuits = bundles.flatMap((b) => b.circuits);
  const title = { switch: "Switch", edge: "Network Edge device", port: "Fabric port", metro: "Other metro", provider: "Provider", other: "Other parties" }[
    node.kind
  ];
  return (
    <aside className="netmap-clients equinix-panel" aria-label="Details">
      <header>
        {title}
        <button type="button" onClick={onClose} aria-label="Close details">
          Close
        </button>
      </header>
      <dl className="netmap-linkends">
        <dt>Name</dt>
        <dd>{node.name}</dd>
        {port && (
          <>
            <dt>IBX</dt>
            <dd>{port.ibx ?? "not known"}</dd>
            <dt>State</dt>
            <dd>{port.state ?? "not known"}</dd>
            <dt>Speed</dt>
            <dd>{port.speed_mbps != null ? `${port.speed_mbps} Mbit/s` : "not known"}</dd>
            <dt>Redundancy</dt>
            <dd>{[port.redundancy, port.lag ? `LAG ${port.lag}` : null].filter(Boolean).join(", ") || "not known"}</dd>
            <dt>Cable ID</dt>
            <dd className="netmap-port">{port.cable_ids.join(", ") || "not known"}</dd>
            <dt>Switch port</dt>
            <dd>
              {port.bound ? (
                <>
                  {data.devices.find((d) => d.uid === port.bound!.device)?.name ?? port.bound.device}{" "}
                  <span className="netmap-port">{port.bound.port_name ?? "not known"}</span>
                </>
              ) : (
                unboundText(port)
              )}
            </dd>
          </>
        )}
        {edge && (
          <>
            <dt>Model</dt>
            <dd>{[edge.vendor, edge.model].filter(Boolean).join(" ") || "not known"}</dd>
            <dt>Status</dt>
            <dd>{edge.status ?? "not known"}</dd>
            <dt>Same device as</dt>
            <dd>{edge.same_as_name ?? edge.same_as ?? (edge.bound_device ? `${edge.bound_device} (not in this run)` : "no binding")}</dd>
          </>
        )}
        {node.kind === "switch" && (
          <>
            <dt>Fabric ports</dt>
            <dd>
              {switchPorts.map((p) => (
                <div key={p.uid}>
                  <span className="netmap-port">{p.bound?.port_name ?? "not known"}</span> {p.name}
                </div>
              ))}
            </dd>
          </>
        )}
      </dl>
      {circuits.length > 0 && <CircuitTable circuits={circuits} />}
    </aside>
  );
}

function QueryList({ queries, metro }: { queries: EquinixQuery[]; metro: string | null }) {
  const workspace = useWorkspace();
  if (queries.length === 0) return <div className="netmap-empty">No Equinix query in the catalog</div>;
  return (
    <div className="netmap-tabbody equinix-queries">
      <ul>
        {queries.map((q) => (
          <li key={q.key}>
            <div>
              <strong>{q.title}</strong>
              {q.description && <div className="dim">{q.description}</div>}
            </div>
            <button
              type="button"
              disabled={!workspace}
              onClick={() => workspace?.openQuery(q.key, false, metro ? { metro } : undefined)}
            >
              Open in Explore
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
