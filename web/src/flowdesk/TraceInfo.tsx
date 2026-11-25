/** TracePage owns `open` and persists it under `hst.trace.info.open`. */

import { useNamer } from "../shell/deviceNames";
import { Icon } from "../shell/icons";
import { useState } from "react";
import type { PathResponse } from "../api/types";

const COLLAPSE_AT = 4;

export function TraceInfo({
  result,
  open,
  onToggle,
}: {
  result: PathResponse | null;
  open: boolean;
  onToggle: () => void;
}) {
  const [notesOpen, setNotesOpen] = useState(false);
  const name = useNamer();
  if (!result) return null;

  const warnings = (result.warnings ?? []).map(name);
  const seen = new Set(warnings);
  const notes = (result.notes ?? []).map(name).filter((n) => !seen.has(n));
  if (warnings.length === 0 && notes.length === 0) return null;

  const lines = [...warnings, ...notes];

  // the warnings always show
  const shown = notesOpen ? notes : notes.slice(0, COLLAPSE_AT);
  const hidden = notes.length - shown.length;

  return (
    <div className="traceinfo">
      <button type="button" className="tb-head" aria-expanded={open} onClick={onToggle}>
        <span className={"tb-chevron" + (open ? " open" : "")}>
          <Icon name="chevron-right" size={12} />
        </span>
        <span className="tb-title">Info</span>
        <span className="tb-preview">{lines[0]}</span>
      </button>
      {open && (
        <div className="collapsible-body">
          <ul>
            {warnings.map((w, i) => (
              <li key={`w${i}`} className="warn">
                <span className="traceinfo-tag">Warning</span> {w}
              </li>
            ))}
            {shown.map((n, i) => (
              <li key={`n${i}`}>{n}</li>
            ))}
          </ul>
          {(hidden > 0 || notesOpen) && (
            <button type="button" className="linkish" onClick={() => setNotesOpen((v) => !v)}>
              {notesOpen ? "Fewer" : `${hidden} more`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
