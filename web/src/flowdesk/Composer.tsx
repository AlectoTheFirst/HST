/** The optional start VRF starts the trace in a VRF by its name. */

import { useId, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { MtuRequest, StartVrf, StartVrfList } from "../api/types";
import { Icon } from "../shell/icons";
import { writeJson } from "../shell/storage";
import { MtuControls, initialMtuRequest, submittedMtuRequest, MTU_QUERY_KEY } from "./MtuControls";
import { SnapshotPicker } from "./SnapshotPicker";

export interface TraceParams {
  src: string;
  dst: string;
  port: string;
  proto: string;
  /** Pin the trace to an archived run; absent/"" means the live graph. */
  snapshot?: string;
  /** The VRF the trace starts in, a name from GET /api/path/vrfs. Absent means
   *  the trace starts at the gateway of the source. */
  startVrf?: string;
  /** A second run to compare against, from the "compare" checkbox's picker. */
  compareWith?: string;
  /** Also trace the reply. Absent means forward only. */
  reply?: boolean;
  mtu?: MtuRequest;
}

const DEFAULTS: TraceParams = { src: "192.168.10.0/24", dst: "8.8.8.8", port: "443", proto: "tcp" };

/** The result is "" for an empty field and null for a text that names no VRF of the run. */
function resolveStartVrf(text: string, vrfs: StartVrf[]): string | null {
  const wanted = text.trim();
  if (!wanted) return "";
  const match = vrfs.find((v) => v.name === wanted);
  return match ? match.name : null;
}

export function Composer({
  onTrace,
  tracing,
  advancedExtra,
}: {
  onTrace: (params: TraceParams) => void;
  tracing: boolean;
  /** Rendered at the end of the Advanced options block: the page's own
   *  follow-up actions on the last result (TracePage's "Investigate evidence"). */
  advancedExtra?: React.ReactNode;
}) {
  const [mtu, setMtu] = useState<MtuRequest>(initialMtuRequest);
  const [src, setSrc] = useState(DEFAULTS.src);
  const [dst, setDst] = useState(DEFAULTS.dst);
  const [port, setPort] = useState(DEFAULTS.port);
  const [proto, setProto] = useState(DEFAULTS.proto);
  const [snapshot, setSnapshot] = useState("");
  const [startVrf, setStartVrf] = useState("");
  const vrfs = useQuery({
    queryKey: ["path-vrfs", snapshot],
    queryFn: () => api<StartVrfList>(snapshot ? `/path/vrfs?snapshot=${encodeURIComponent(snapshot)}` : "/path/vrfs"),
  });
  const vrfOptions = vrfs.data?.vrfs ?? [];
  // A VRF that is not in the picked run is never sent.
  const startName = resolveStartVrf(startVrf, vrfOptions);
  // Compare, reply and the MTU size modes apply only while "Advanced options" is open.
  const [advanced, setAdvanced] = useState(false);
  const [compare, setCompare] = useState(false);
  const [compareWith, setCompareWith] = useState("");
  const [reply, setReply] = useState(false);
  const id = useId();

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const trimmedSrc = src.trim();
    const trimmedDst = dst.trim();
    if (!trimmedSrc || !trimmedDst || startName === null) return;
    onTrace({
      src: trimmedSrc,
      dst: trimmedDst,
      port: port.trim(),
      proto,
      mtu: advanced ? submittedMtuRequest(mtu, trimmedDst.includes(":"), reply) : { mode: "inventory" },
      snapshot: snapshot || undefined,
      startVrf: startName || undefined,
      compareWith: advanced && compare ? compareWith || undefined : undefined,
      reply: advanced && reply,
    });
  }

  return (
    <form className="composer" onSubmit={handleSubmit} aria-label="Trace a flow">
      <div className="composer-row">
        <label className="field" htmlFor={`${id}-start-vrf`}>
          <span className="field-label">Start VRF</span>
          <input
            id={`${id}-start-vrf`}
            className="f-start-vrf"
            aria-label="Start VRF"
            aria-invalid={startName === null}
            aria-describedby={startName === null ? `${id}-start-vrf-error` : undefined}
            list={`${id}-start-vrfs`}
            placeholder="none"
            spellCheck={false}
            autoComplete="off"
            value={startVrf}
            onChange={(e) => setStartVrf(e.target.value)}
          />
          <datalist id={`${id}-start-vrfs`}>
            {vrfOptions.map((v) => (
              <option key={v.name} value={v.name} />
            ))}
          </datalist>
          {vrfs.isError ? (
            <span id={`${id}-start-vrf-error`} className="field-error" role="alert">
              VRFs not loaded
            </span>
          ) : (
            startName === null && (
              <span id={`${id}-start-vrf-error`} className="field-error">
                not a VRF in this run
              </span>
            )
          )}
        </label>
        <label className="field" htmlFor={`${id}-src`}>
          <span className="field-label">Source</span>
          <input
            id={`${id}-src`}
            className="f-src"
            aria-label="Source"
            spellCheck={false}
            value={src}
            onChange={(e) => setSrc(e.target.value)}
          />
        </label>
        <span className="arrow">
          <Icon name="arrow-right" />
        </span>
        <label className="field" htmlFor={`${id}-dst`}>
          <span className="field-label">Destination</span>
          <input
            id={`${id}-dst`}
            className="f-dst"
            aria-label="Destination"
            spellCheck={false}
            value={dst}
            onChange={(e) => setDst(e.target.value)}
          />
        </label>
        <label className="field" htmlFor={`${id}-port`}>
          <span className="field-label">Port</span>
          <input
            id={`${id}-port`}
            className="f-port"
            aria-label="Port"
            spellCheck={false}
            inputMode="numeric"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </label>
        <label className="field" htmlFor={`${id}-proto`}>
          <span className="field-label">Protocol</span>
          <select
            id={`${id}-proto`}
            aria-label="Protocol"
            value={proto}
            onChange={(e) => setProto(e.target.value)}
          >
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
          </select>
        </label>
        <SnapshotPicker value={snapshot} onChange={setSnapshot} label="Snapshot" allowCurrent />
        <button
          type="button"
          className="linkish advanced-toggle"
          aria-expanded={advanced}
          onClick={() => setAdvanced((open) => !open)}
        >
          Advanced options
          <Icon name={advanced ? "chevron-down" : "chevron-right"} size={14} />
        </button>
        <span className="go">
          <button className="primary" type="submit" disabled={tracing}>
            {tracing ? "Tracing" : "Trace flow"}
          </button>
        </span>
      </div>
      {advanced && (
        <div className="composer-advanced" role="group" aria-label="Advanced options">
          <label className="compare-toggle">
            <input
              type="checkbox"
              checked={reply}
              onChange={(e) => setReply(e.target.checked)}
              aria-label="Also trace the reply"
            />
            Also trace the reply
          </label>
          <label className="compare-toggle">
            <input
              type="checkbox"
              checked={compare}
              onChange={(e) => setCompare(e.target.checked)}
            />
            Compare
          </label>
          {compare && (
            <SnapshotPicker value={compareWith} onChange={setCompareWith} label="Compare with" allowCurrent />
          )}
          <MtuControls value={mtu} onChange={(next) => { setMtu(next); writeJson(MTU_QUERY_KEY, next); }} ipv6={dst.includes(":")} replyEnabled={reply} />
          {advancedExtra}
        </div>
      )}
    </form>
  );
}
