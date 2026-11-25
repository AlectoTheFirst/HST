import { useEffect, useState } from "react";
import type { Segment, Source } from "../data/api";

interface Props {
  source: Source;
  uid: string;
  run: number;
  device: string;
  onClose: () => void;
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** The segment expansion: the segment's prefix and VLAN, and its clients with name, IP, MAC, port and last seen. */
export default function SegmentModal({ source, uid, run, device, onClose }: Props) {
  const key = `${uid}@${run}`;
  const [loaded, setLoaded] = useState<{ key: string; segment: Segment } | null>(null);
  const [error, setError] = useState<{ key: string; text: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    source.segment(uid, run).then(
      (segment) => {
        if (!cancelled) setLoaded({ key, segment });
      },
      (e) => {
        if (!cancelled) setError({ key, text: message(e) });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [source, uid, run, key]);

  const segment = loaded?.key === key ? loaded.segment : null;
  const failed = error?.key === key ? error.text : null;
  const title = segment ? (segment.prefix ?? (segment.vid !== null ? `VLAN ${segment.vid}` : (segment.name ?? "Segment"))) : "Segment";
  return (
    <section className="hst-cable hst-segment" aria-label="Segment clients">
      <header>
        <h3>
          {title}
          <span className="hst-cable-to"> on </span>
          {device}
        </h3>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </header>
      {segment && (
        <p className="hint">
          {[segment.name, segment.vid !== null ? `VLAN ${segment.vid}` : null, segment.prefix].filter(Boolean).join(", ")}
        </p>
      )}
      {!segment && !failed && <p className="hint">Loading the clients</p>}
      {failed && (
        <p className="hst-error" role="alert">
          {failed}
        </p>
      )}
      {segment && segment.state === "cold" && <p className="hint">Cold run</p>}
      {segment && segment.state === "warm" && segment.clients.length === 0 && <p className="hint">No client at this run</p>}
      {segment && segment.clients.length > 0 && (
        <table className="hst-segment-clients">
          <thead>
            <tr>
              <th>Name</th>
              <th>IP address</th>
              <th>MAC</th>
              <th>Port</th>
            </tr>
          </thead>
          <tbody>
            {segment.clients.map((c) => (
              <tr key={c.uid}>
                <td>{c.name ?? "unknown"}</td>
                <td>{c.ip.join(", ")}</td>
                <td>{c.mac ?? ""}</td>
                <td>{c.port ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
