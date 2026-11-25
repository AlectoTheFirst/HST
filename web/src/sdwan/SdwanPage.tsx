/**
 * The SD-WAN pane: pick one edge, and see its WAN links, its tunnels, the
 * hubs, branches and cloud gateways where the tunnels end, the switches that the hubs
 * are cabled to, and the business policy of the edge as a table of rules.
 */

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type { SdwanEdgesResponse, SdwanTopology } from "../api/types";
import { useCanvas, type Point } from "../diagram/useCanvas";
import { chipPath, control } from "../diagram/diagram";
import { layoutSdwan, type SdwanNode, type SdwanNodeKind } from "./layout";
import { bySegment, gapSentence, matchCell, qosCell, routeLines, slaCell } from "./policy";
import { rovingKeys, rovingTabIndex } from "../shell/rovingKeys";
import "../diagram/netmap.css";
import "./sdwan.css";
import "../diagram/diagram.css";

// px between parallel cables of one device pair
const LANE_GAP = 8;

type Mode = "topology" | "policy";
type Panel = { kind: "node"; uid: string } | { kind: "tunnel"; uid: string } | { kind: "cable"; index: number };

const NODE_TITLE: Record<SdwanNodeKind, string> = {
  device: "Device",
  hub: "Hub",
  branches: "Branches",
  gateway: "Cloud gateway",
  edge: "Edge",
  link: "WAN link",
};

function edgeLabel(e: SdwanEdgesResponse["edges"][number]): string {
  return e.role === "hub" ? `${e.name} (hub)` : e.name;
}

/** One label for each edge uid. A label that two edges share gets the site or
 *  the location, and then the uid, so every edge can be picked. */
export function edgeLabels(edges: SdwanEdgesResponse["edges"]): Map<string, string> {
  const count = (labels: string[]) => {
    const n = new Map<string, number>();
    for (const l of labels) n.set(l, (n.get(l) ?? 0) + 1);
    return n;
  };
  const base = edges.map(edgeLabel);
  const baseCount = count(base);
  const second = edges.map((e, i) =>
    (baseCount.get(base[i]) ?? 0) > 1 ? `${base[i]}, ${e.site ?? e.location ?? e.country ?? e.uid}` : base[i],
  );
  const secondCount = count(second);
  return new Map(
    edges.map((e, i) => [e.uid, (secondCount.get(second[i]) ?? 0) > 1 ? `${second[i]}, ${e.uid}` : second[i]]),
  );
}

function mbps(value: number | null): string {
  return value == null ? "not known" : `${value} Mbit/s`;
}

function edgeCount(n: number): string {
  if (n === 0) return "No SD-WAN edge";
  return n === 1 ? "1 edge" : `${n} edges`;
}

export default function SdwanPage() {
  const [edge, setEdge] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [mode, setMode] = useState<Mode>("topology");
  const [panel, setPanel] = useState<Panel | null>(null);

  const edges = useQuery({
    queryKey: ["sdwan-edges"],
    queryFn: () => api<SdwanEdgesResponse>("/sdwan/edges"),
  });
  const labels = useMemo(() => edgeLabels(edges.data?.edges ?? []), [edges.data]);
  const byLabel = useMemo(() => new Map([...labels].map(([uid, label]) => [label, uid])), [labels]);
  const topology = useQuery({
    queryKey: ["sdwan-topology", edge],
    queryFn: () => api<SdwanTopology>(`/sdwan/topology?edge=${encodeURIComponent(edge!)}`),
    enabled: edge !== null,
  });

  const toolbar = (
    <div className="netmap-toolbar">
      <input
        className="sdwan-picker"
        list="sdwan-edges"
        aria-label="SD-WAN edge"
        placeholder={edges.isLoading ? "Loading edges" : "Edge name"}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          const uid = byLabel.get(e.target.value);
          if (uid) {
            setEdge(uid);
            setPanel(null);
          }
        }}
      />
      <datalist id="sdwan-edges">
        {(edges.data?.edges ?? []).map((e) => (
          <option key={e.uid} value={labels.get(e.uid)}>
            {e.location ?? ""}
          </option>
        ))}
      </datalist>
      <div className="segs netmap-layers" role="radiogroup" aria-label="SD-WAN view">
        {(
          [
            ["topology", "Topology"],
            ["policy", "Business policy"],
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
    </div>
  );

  let body;
  if (edges.error) {
    body = <div className="netmap-empty">Edge list not loaded: {String(edges.error)}</div>;
  } else if (edge === null) {
    body = (
      <div className="netmap-empty">
        {edges.data ? edgeCount(edges.data.edges.length) : "Loading edges"}
      </div>
    );
  } else if (topology.isLoading) {
    body = <div className="netmap-empty">Loading edge</div>;
  } else if (topology.error) {
    body = (
      <div className="netmap-empty">
        {topology.error instanceof ApiError && topology.error.status === 404
          ? "Edge not in the pinned run"
          : `Edge not loaded: ${String(topology.error)}`}
      </div>
    );
  } else if (topology.data) {
    body =
      mode === "topology" ? (
        <Diagram data={topology.data} panel={panel} setPanel={setPanel} />
      ) : (
        <PolicyTable data={topology.data} />
      );
  }

  return (
    <div className="netmap">
      {toolbar}
      {body}
    </div>
  );
}

/** The shared chip style of a node kind. */
function chipRole(kind: string): string {
  if (kind === "edge" || kind === "hub") return "netmap-chip-device";
  if (kind === "link") return "netmap-chip-far";
  return "";
}

function cablePath(a: Point & { h: number }, b: Point & { h: number }, lane: number): string {
  return chipPath(a, b, lane, LANE_GAP);
}

function Diagram({
  data,
  panel,
  setPanel,
}: {
  data: SdwanTopology;
  panel: Panel | null;
  setPanel: (p: Panel | null) => void;
}) {
  const layout = useMemo(() => layoutSdwan(data), [data]);
  const { svg, viewBox, handlers } = useCanvas(layout.fit, {
    dragAttr: "data-drag",
    passthrough: "[data-cable], [data-node]",
  });
  const home = useMemo(() => new Map(layout.nodes.map((n) => [n.uid, n])), [layout]);
  const at = (uid: string): SdwanNode | undefined => home.get(uid);
  const nameOf = (uid: string) => home.get(uid)?.name ?? uid;

  // with a node picked, its tunnels and cables stay lit and the rest fades
  const picked = panel?.kind === "node" ? panel.uid : null;
  const touches = (a: string, b: string) => picked === null || a === picked || b === picked;

  const tunnel = panel?.kind === "tunnel" ? layout.tunnels.find((t) => t.uid === panel.uid) : undefined;
  const cable = panel?.kind === "cable" ? layout.cables[panel.index] : undefined;
  const node = picked ? home.get(picked) : undefined;
  const link = node?.kind === "link" ? data.links.find((l) => l.uid === node.uid) : undefined;

  return (
    <>
      <svg
        ref={svg}
        className="netmap-canvas"
        viewBox={viewBox}
        role="group"
        aria-label="SD-WAN topology"
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
        {layout.tunnels.map((t) => {
          const a = at(t.from);
          const b = at(t.to);
          if (!a || !b) return null;
          const on = panel?.kind === "tunnel" && panel.uid === t.uid;
          const d = cablePath(a, b, t.lane);
          return (
            <g
              key={t.uid}
              className={
                `netmap-cable sdwan-tunnel sdwan-tunnel-${t.kind}` +
                (on ? " on" : "") +
                (touches(t.from, t.to) ? "" : " netmap-dim")
              }
              data-cable
              {...control(`Tunnel ${t.interface} to ${nameOf(t.to)}`, () => setPanel(on ? null : { kind: "tunnel", uid: t.uid }), on)}
            >
              <path className="netmap-cablehit" d={d} />
              <path d={d}>
                <title>{`${t.interface} to ${nameOf(t.to)}${t.peerIp ? ` (${t.peerIp})` : ""}`}</title>
              </path>
            </g>
          );
        })}
        {layout.cables.map((c, i) => {
          const a = at(c.a);
          const b = at(c.b);
          if (!a || !b) return null;
          const on = panel?.kind === "cable" && panel.index === i;
          const d = cablePath(a, b, c.lane);
          return (
            <g
              key={`cable-${i}`}
              className={"netmap-cable" + (on ? " on" : "") + (touches(c.a, c.b) ? "" : " netmap-dim")}
              data-cable
              {...control(`Cable ${c.aPort} to ${c.bPort}`, () => setPanel(on ? null : { kind: "cable", index: i }), on)}
            >
              <path className="netmap-cablehit" d={d} />
              <path d={d}>
                <title>{`${c.aPort} to ${c.bPort}`}</title>
              </path>
            </g>
          );
        })}
        {layout.nodes.map((n) => {
          const on = picked === n.uid;
          return (
            <g
              key={n.uid}
              className={`netmap-node netmap-chip sdwan-${n.kind} ${chipRole(n.kind)}` + (on ? " on" : "")}
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
      {tunnel && (
        <aside className="netmap-clients" aria-label="Tunnel details">
          <header>
            Tunnel
            <button type="button" onClick={() => setPanel(null)} aria-label="Close tunnel details">
              Close
            </button>
          </header>
          <dl className="netmap-linkends">
            <dt>From</dt>
            <dd>
              {data.edge.name} <span className="netmap-port">{tunnel.interface || "not known"}</span>
            </dd>
            <dt>To</dt>
            <dd>
              {nameOf(tunnel.to)} <span className="netmap-port">{tunnel.kind}</span>
            </dd>
            {tunnel.count > 1 && (
              <>
                <dt>Tunnels</dt>
                <dd>{tunnel.count}</dd>
              </>
            )}
            {tunnel.peerIp && (
              <>
                <dt>Address</dt>
                <dd className="netmap-port">{tunnel.peerIp}</dd>
              </>
            )}
          </dl>
        </aside>
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
            <dt>A</dt>
            <dd>
              {nameOf(cable.a)} <span className="netmap-port">{cable.aPort || "not known"}</span>
            </dd>
            <dt>B</dt>
            <dd>
              {nameOf(cable.b)} <span className="netmap-port">{cable.bPort || "not known"}</span>
            </dd>
            {cable.source && (
              <>
                <dt>Source</dt>
                <dd>{cable.source}</dd>
              </>
            )}
          </dl>
        </aside>
      )}
      {node && (
        <aside className="netmap-clients" aria-label="Device details">
          <header>
            {NODE_TITLE[node.kind]}
            <button type="button" onClick={() => setPanel(null)} aria-label="Close details">
              Close
            </button>
          </header>
          <dl className="netmap-linkends">
            <dt>Name</dt>
            <dd>{node.name}</dd>
            {link ? (
              <>
                <dt>Interface</dt>
                <dd className="netmap-port">{link.interface ?? "not known"}</dd>
                <dt>Provider</dt>
                <dd>{link.provider ?? link.carrier ?? "not known"}</dd>
                <dt>Kind</dt>
                <dd>{[link.kind, link.mode].filter(Boolean).join(", ") || "not known"}</dd>
                <dt>Public IP</dt>
                <dd className="netmap-port">{link.public_ip ?? "not known"}</dd>
                <dt>Speed</dt>
                <dd>
                  {mbps(link.down_mbps)} down, {mbps(link.up_mbps)} up
                </dd>
                {link.backup_only && (
                  <>
                    <dt>Use</dt>
                    <dd>backup only</dd>
                  </>
                )}
              </>
            ) : (
              node.caption && (
                <>
                  <dt>Details</dt>
                  <dd>{node.caption}</dd>
                </>
              )
            )}
            {node.members && (
              <>
                <dt>Branches</dt>
                <dd>{node.members.join(", ")}</dd>
              </>
            )}
            <dt>Tunnels</dt>
            <dd>
              {layout.tunnels
                .filter((t) => t.from === node.uid || t.to === node.uid)
                .reduce((n, t) => n + t.count, 0)}
            </dd>
          </dl>
        </aside>
      )}
    </>
  );
}

function PolicyTable({ data }: { data: SdwanTopology }) {
  const policy = data.policy;
  if (!policy) return <div className="netmap-empty">No business policy</div>;
  if (policy.capability_gap) {
    return (
      <div className="netmap-tabbody sdwan-policy">
        <h3>{policy.name ?? "Business policy"}</h3>
        <p className="sdwan-gap">{gapSentence(policy.capability_gap)}</p>
      </div>
    );
  }
  if (policy.rule_count == null) {
    return (
      <div className="netmap-empty">
        No policy rules
      </div>
    );
  }
  return (
    <div className="netmap-tabbody sdwan-policy">
      <h3>
        {policy.name ?? "Business policy"}
      </h3>
      {bySegment(policy.rules).map((g) => (
        <section key={g.segment}>
          <h4>Segment {g.segment || "not known"}</h4>
          <table>
            <thead>
              <tr>
                <th>Position</th>
                <th>Rule</th>
                <th>Match</th>
                <th>QoS</th>
                <th>Route</th>
                <th>SLA and NAT</th>
              </tr>
            </thead>
            <tbody>
              {g.rules.map((r) => (
                <tr key={`${g.segment}:${r.position}`} className={r.default ? "sdwan-default" : ""}>
                  <td className="dim">{r.position}</td>
                  <td>
                    {r.name ?? "not known"}
                    {r.default && <span className="sdwan-tag">default</span>}
                  </td>
                  <td>{matchCell(r)}</td>
                  <td>{qosCell(r)}</td>
                  <td>
                    {routeLines(r).map((l) => (
                      <div key={l.target}>
                        <span className="dim">{l.target}:</span> {l.text}
                      </div>
                    ))}
                  </td>
                  <td>{slaCell(r)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}
    </div>
  );
}
