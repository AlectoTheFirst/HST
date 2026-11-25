import { useEffect, useState } from "react";
import { ApiError } from "../../api/client";
import type { InterfaceFacts, InterfaceText, Source } from "../data/api";
import { sideBySide } from "./diff";

/** A pinned interface state, the A side of a comparison. */
export interface Pin {
  uid: string;
  run: number;
  label: string;
  lines: string[];
}

interface Props {
  source: Source;
  uid: string;
  run: number;
  runLabel: string;
  /** The caller holds `interfaces.read` and sees the configuration, not only the facts. */
  canReadText: boolean;
  pinned: Pin | null;
  onPin(pin: Pin): void;
  onClose(): void;
  /** Starts a regression assessment from run A to run B; absent outside the workspace. */
  onRegression?(before: number, after: number): void;
}

interface Loaded {
  key: string;
  facts: InterfaceFacts | null;
  text: InterfaceText | null;
  note: string | null;
}

function value(v: unknown): string {
  return Array.isArray(v) ? v.join(", ") : typeof v === "object" && v !== null ? JSON.stringify(v) : String(v);
}

/** The facts as `key: value` lines, compared when the configuration is not readable. */
export function factLines(f: InterfaceFacts): string[] {
  const lines = [`name: ${f.name ?? ""}`, `device: ${f.device_uid ?? ""}`];
  for (const [prefix, props] of [
    ["interface", f.interface],
    ["port", f.port],
  ] as const) {
    for (const [k, v] of Object.entries(props ?? {})) lines.push(`${prefix}.${k}: ${value(v)}`);
  }
  lines.push(`contexts: ${f.contexts.join(", ")}`, `addresses: ${f.addresses.join(", ")}`, `lags: ${f.lags.join(", ")}`);
  return lines;
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export default function Overlay({ source, uid, run, runLabel, canReadText, pinned, onPin, onClose, onRegression }: Props) {
  const key = `${uid}@${run}`;
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [compare, setCompare] = useState(false);
  const [error, setError] = useState<{ key: string; text: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const text = canReadText
      ? source.interfaceText(uid, run).then(
          (t) => ({ text: t, note: null }),
          (e) => ({ text: null, note: e instanceof ApiError && e.status === 404 ? "No configuration collected" : message(e) }),
        )
      : Promise.resolve({ text: null, note: "No interfaces.read permission" });
    Promise.all([source.interface(uid, run), text]).then(
      ([facts, t]) => {
        if (!cancelled) setLoaded({ key, facts, text: t.text, note: t.note });
      },
      (e) => {
        if (!cancelled) setError({ key, text: message(e) });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [source, uid, run, key, canReadText]);

  const current = loaded?.key === key ? loaded : null;
  const failed = error?.key === key ? error.text : null;
  const lines = current ? (current.text ? current.text.text.split("\n") : current.facts ? factLines(current.facts) : []) : [];
  const pairs = compare && pinned && current ? sideBySide(pinned.lines, lines) : null;

  return (
    <section className="hst-overlay" aria-label="Interface overlay">
      <header>
        <h3>Interface at {runLabel}</h3>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </header>
      {!current && !failed && <p className="hint">Loading the interface</p>}
      {failed && (
        <p className="hst-error" role="alert">
          {failed}
        </p>
      )}
      {current?.facts && (
        <p className="hst-overlay-name">
          {current.facts.name ?? uid} on {current.facts.device_uid ?? "unknown device"}
        </p>
      )}
      {current && (
        <div className="hst-overlay-actions">
          <button type="button" onClick={() => onPin({ uid, run, label: runLabel, lines })}>
            Pin A
          </button>
          <button type="button" disabled={!pinned} onClick={() => setCompare((c) => !c)} aria-pressed={compare}>
            Compare with B
          </button>
          {pinned && <span className="hst-overlay-pin">A: {pinned.label}</span>}
          {compare && pinned && pinned.run !== run && onRegression && (
            <button type="button" onClick={() => onRegression(pinned.run, run)}>
              Explain this regression
            </button>
          )}
        </div>
      )}
      {current?.note && <p className="hint">{current.note}</p>}
      {current?.text && <p className="hst-overlay-command">{current.text.command}</p>}
      {pairs ? (
        <table className="hst-diff" aria-label="Comparison of A and B">
          <thead>
            <tr>
              <th scope="col">A: {pinned!.label}</th>
              <th scope="col">B: {runLabel}</th>
            </tr>
          </thead>
          <tbody>
            {pairs.map((p, i) => (
              <tr key={i} className={`hst-diff-${p.kind}`} data-kind={p.kind}>
                <td>{p.a ?? ""}</td>
                <td>{p.b ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        current && <pre className="hst-overlay-text">{lines.join("\n")}</pre>
      )}
    </section>
  );
}
