/** TracePage owns `open` and persists it under `hst.trace.inspector.open`. */

import { useNamer } from "../shell/deviceNames";
import { Icon } from "../shell/icons";
import { MtuDetails, MtuLegSummary } from "./MtuPanel";
import { useState } from "react";
import type { Leg, PathResponse } from "../api/types";
import { legOutcome } from "./verdict";
import { exitText, legExits } from "./traceResult";
import type { Selection } from "./selection";

// The fact of a leg a gate on it did not decide.
const NOT_DECIDED = "not decided";

function legFacts(leg: Leg): string[] {
  const out = [leg.detail, leg.src_label];
  if (leg.cidr) out.push(`${leg.cidr}${leg.egress ? ` via ${leg.egress}` : ""}`);
  else if (leg.egress) out.push(`via ${leg.egress}`);
  if (leg.next_hop) out.push(`next-hop ${leg.next_hop}`);
  if (leg.table && leg.table !== "-") out.push(`table ${leg.table}`);
  if (leg.firewall) out.push(leg.firewall);
  for (const d of leg.dnat ?? []) {
    const view = d.filter_view ? ` (policy on the ${d.filter_view} destination)` : "";
    out.push(`dNAT to ${d.to.join(", ")}${d.port ? `:${d.port}` : ""}${view}`);
  }
  for (const s of leg.snat ?? []) out.push(`sNAT ${s.sources.join(", ")} to ${s.to}`);
  if (leg.carrier) {
    const c = leg.carrier;
    const to = `${c.endpoint}${c.port ? `:${c.port}` : ""}${c.proto ? `/${c.proto}` : ""}`;
    out.push(`carrier ${to}: ${c.detail}`);
    if (c.snat) out.push(`carrier sNAT to ${c.snat}`);
  }
  for (const exit of legExits(leg)) out.push(`left estate ${exitText(exit)}`);
  // a blocked leg can also be one no gate decided: it says both
  if (leg.indeterminate || leg.result?.answer === "open") out.push(NOT_DECIDED);
  return out;
}

export function Inspector({
  selection,
  result,
  open,
  onToggle,
}: {
  selection: Selection | null;
  result?: PathResponse | null;
  open: boolean;
  onToggle: () => void;
}) {
  const [rawOpen, setRawOpen] = useState(false);
  const name = useNamer();

  if (!selection) {
    return (
      <div className="inspector">
        <div className="card-title">Node details</div>
        <span className="hint">No node selected</span>
      </div>
    );
  }

  const leg =
    selection.type === "leg"
      ? selection.data
      : result?.legs.find((l) => l.lane === selection.data.lane);

  const { type, data } = selection;
  const label = type === "hop" ? data.label : data.result.word;
  const kind = type === "hop" ? data.kind : `leg ${data.lane}`;
  const note = type === "hop" ? data.note : (data.firewall ?? "");
  const uid =
    type === "hop"
      ? `uid ${data.uid}`
      : `egress ${data.egress ?? "none"}, table ${data.table ?? "none"}`;
  const color =
    type === "hop"
      ? `var(--kind-${data.kind}, var(--kind-fallback))`
      : legOutcome(data) === "bad"
        ? "var(--bad)"
        : legOutcome(data) === "warn"
          ? "var(--warn)"
          : "var(--ok)";
  const raw = JSON.stringify(data, null, 1);

  return (
    <div className="inspector">
      <div className="card-title">Node details</div>
      <button type="button" className="tb-head" aria-expanded={open} onClick={onToggle}>
        <span className={"tb-chevron" + (open ? " open" : "")}>
          <Icon name="chevron-right" size={12} />
        </span>
        <span className="who">
          <span className="kdot" style={{ background: color }} />
          <span className="name">{label}</span>
          <span className="kind">{kind}</span>
        </span>
      </button>
      {open && (
        <div className="collapsible-body">
          <div className="row">
            <span className="note">{name(note)}</span>
            <span className="uid">{uid}</span>
            <button type="button" className="linkish" onClick={() => setRawOpen((v) => !v)}>
              {rawOpen ? "Hide raw evidence" : "Show raw evidence"}
            </button>
          </div>
          {leg && (result?.legs.length ?? 0) > 0 && (
            <div className="inspector-leg">
              <span className="kind">leg {leg.lane}</span>
              {legFacts(leg).map((f, i) => (
                <span key={i} className={f === NOT_DECIDED ? "bad" : undefined}>
                  {name(f)}
                </span>
              ))}
              <MtuLegSummary result={result?.mtu} lane={leg.lane} />
            </div>
          )}
          {leg?.sdwan_rules?.length ? (
            <table className="inspector-rules" aria-label="SD-WAN business policy rules">
              <thead>
                <tr>
                  <th scope="col">Position</th>
                  <th scope="col">Rule</th>
                  <th scope="col">Result</th>
                  <th scope="col">Not decided</th>
                  <th scope="col">Action</th>
                  <th scope="col">Candidates</th>
                </tr>
              </thead>
              <tbody>
                {leg.sdwan_rules.map((r) => (
                  <tr key={`${r.position}:${r.name}`}>
                    <td>{r.position ?? ""}</td>
                    <td>{r.name ?? ""}</td>
                    <td>{r.result.word}</td>
                    <td>{r.undecided}</td>
                    <td>{r.action}</td>
                    <td>{r.candidates}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
          <MtuDetails result={result?.mtu} subjectUid={selection.type === "hop" ? selection.data.uid : undefined} lane={selection.type === "hop" && selection.data.shared ? undefined : String(selection.data.lane)} />
          {rawOpen && <pre className="rawpre">{raw}</pre>}
        </div>
      )}
    </div>
  );
}
