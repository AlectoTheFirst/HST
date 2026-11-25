import { useEffect, useState } from "react";
import { ApiError } from "../../api/client";
import type { Source } from "../data/api";
import type { Row } from "../render/types";
import { changedSince } from "./diff";
import { factLines } from "./Overlay";

/** One end of a cable: its port uid and the names it shows under. */
export interface CableEnd {
  port: string;
  device: string;
  name: string;
}

export interface Cable {
  id: string;
  a: CableEnd;
  b: CableEnd;
  row: Row;
}

interface Props {
  source: Source;
  cables: Cable[];
  run: number;
  /** The run before `run`, which the changed lines are marked against; null for the first run. */
  previous: number | null;
  /** The caller holds `interfaces.read` and sees the configuration, not only the facts. */
  canReadText: boolean;
  /** The screen point the modal opens next to, inside the map stage. */
  x: number;
  y: number;
  onClose(): void;
}

interface Side {
  lines: string[];
  changed: boolean[];
  command: string | null;
  note: string | null;
}

const WIDTH = 720;
const MARGIN = 12;

function message(e: unknown): string {
  if (e instanceof ApiError && e.status === 404) return "No configuration collected";
  return e instanceof Error ? e.message : String(e);
}

async function side(source: Source, port: string, run: number, previous: number | null, canReadText: boolean): Promise<Side> {
  if (!canReadText) {
    const facts = await source.interface(port, run);
    return { lines: factLines(facts), changed: [], command: null, note: "No interfaces.read permission" };
  }
  try {
    const now = await source.interfaceText(port, run);
    const before = previous === null ? null : await source.interfaceText(port, previous).then((t) => t.text.split("\n"), () => null);
    const lines = now.text.split("\n");
    return { lines, changed: changedSince(before, lines), command: now.command, note: null };
  } catch (e) {
    return { lines: [], changed: [], command: null, note: message(e) };
  }
}

/** The A side and B side configuration of a cable, side by side, next to the cable. */
export default function CableModal({ source, cables, run, previous, canReadText, x, y, onClose }: Props) {
  const [index, setIndex] = useState(0);
  const cable = cables[Math.min(index, cables.length - 1)];
  const key = cable ? `${cable.id}@${run}` : "";
  const [loaded, setLoaded] = useState<{ key: string; a: Side; b: Side } | null>(null);
  const [error, setError] = useState<{ key: string; text: string } | null>(null);

  useEffect(() => {
    if (!cable) return;
    let cancelled = false;
    Promise.all([side(source, cable.a.port, run, previous, canReadText), side(source, cable.b.port, run, previous, canReadText)]).then(
      ([a, b]) => {
        if (!cancelled) setLoaded({ key, a, b });
      },
      (e) => {
        if (!cancelled) setError({ key, text: message(e) });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [source, cable, run, previous, canReadText, key]);

  const current = loaded?.key === key ? loaded : null;
  const failed = error?.key === key ? error.text : null;
  const left = Math.max(MARGIN, x + MARGIN);
  const style = { left: `min(${left}px, calc(100% - ${WIDTH + MARGIN}px))`, top: `${Math.max(MARGIN, y - 40)}px` };

  return (
    <section className="hst-cable" aria-label="Cable configuration" style={style}>
      <header>
        <h3>
          {cable ? `${cable.a.device} ${cable.a.name}` : "Cable"}
          <span className="hst-cable-to"> to </span>
          {cable ? `${cable.b.device} ${cable.b.name}` : ""}
        </h3>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </header>
      {cables.length > 1 && (
        <div className="hst-cable-tabs" role="tablist" aria-label="Cables of this pair">
          {cables.map((c, i) => (
            <button key={c.id} type="button" role="tab" aria-selected={i === index} onClick={() => setIndex(i)}>
              {c.a.name} to {c.b.name}
            </button>
          ))}
        </div>
      )}
      {cables.length === 0 && <p className="hint">No cable loaded</p>}
      {cable && !current && !failed && <p className="hint">Loading the configuration</p>}
      {failed && (
        <p className="hst-error" role="alert">
          {failed}
        </p>
      )}
      {cable && current && (
        <div className="hst-cable-sides">
          {(["a", "b"] as const).map((k) => {
            const s = current[k];
            const end = cable[k];
            return (
              <div key={k} className="hst-cable-side" aria-label={`${k.toUpperCase()} side`}>
                <p className="hst-cable-end">
                  <span className="hst-cable-letter">{k.toUpperCase()}</span> {end.device} {end.name}
                </p>
                {s.command && <p className="hst-overlay-command">{s.command}</p>}
                {s.note && <p className="hint">{s.note}</p>}
                <pre className="hst-cable-text">
                  {s.lines.map((line, i) => (
                    <span key={i} className={s.changed[i] ? "hst-line-changed" : undefined} data-changed={s.changed[i] ? "true" : undefined}>
                      {line}
                      {"\n"}
                    </span>
                  ))}
                </pre>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
