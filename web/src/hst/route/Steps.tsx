import type { Hop } from "../../api/types";
import type { Step } from "./place";

interface Props {
  steps: Step[];
  offMap: Hop[];
  detail: string;
  onStep: (step: Step) => void;
  onClose: () => void;
  /** The trace's lanes (`lanesOf`), the one drawn, and the pick of another. */
  lanes?: number[];
  lane?: number;
  onLane?: (lane: number) => void;
}

/**
 * The step list beside the map: one line per placed hop, the off-map hops after, each line flies to its hop. A trace
 * of 2 lanes or more draws one lane at a time.
 */
export default function Steps({ steps, offMap, detail, onStep, onClose, lanes = [0], lane = 0, onLane }: Props) {
  const others = lanes.length - 1;
  return (
    <aside className="hst-steps" aria-label="Directions">
      <header>
        <h3>Directions</h3>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </header>
      <p className="hst-steps-detail">{detail}</p>
      {others > 0 && (
        <p className="hst-steps-lanes">
          <label>
            Lane{" "}
            <select value={lane} onChange={(e) => onLane?.(Number(e.target.value))}>
              {lanes.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </label>
        </p>
      )}
      <ol>
        {steps.map((s, i) => (
          <li key={`${s.hop.uid}:${i}`} className={s.blocked ? "hst-step-blocked" : undefined}>
            <button type="button" onClick={() => onStep(s)}>
              <span className="hst-step-n">{i === 0 ? "A" : i === steps.length - 1 ? "B" : String(i)}</span>
              <span className="hst-step-label">{s.hop.label}</span>
              <span className="hst-step-note">{s.hop.note}</span>
              {s.word && <span className="hst-step-word">{s.word}</span>}
            </button>
            {s.carrier && (
              <details className="hst-step-carrier">
                <summary>Carrier hops</summary>
                <ol>
                  {s.carrier.map((h, k) => (
                    <li key={`${h.uid}:${k}`}>
                      <span className="hst-step-label">{h.label}</span>
                      <span className="hst-step-note">{h.note}</span>
                    </li>
                  ))}
                </ol>
              </details>
            )}
          </li>
        ))}
      </ol>
      {offMap.length > 0 && (
        <p className="hint">
          Not on the map: {offMap.map((h) => h.label).join(", ")}
        </p>
      )}
    </aside>
  );
}
