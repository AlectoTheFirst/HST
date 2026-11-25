import { useState } from "react";

/**
 * A plain textarea with a line-number gutter. The browser never parses the
 * YAML: the server validates it and returns the line of each error, and the
 * gutter marks the lines listed in `errorLines`. Lines do not wrap, so each
 * gutter number stays beside its line. The gutter is hidden from assistive
 * technology; the caller renders the error text itself.
 */
export function YamlEditor({ id, value, onChange, errorLines, rows = 12 }: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  errorLines?: ReadonlySet<number>;
  rows?: number;
}) {
  const [offset, setOffset] = useState(0);
  const count = value.split("\n").length;
  return <div className="yaml-editor">
    <div className="yaml-editor-gutter" aria-hidden="true">
      <div style={{ transform: `translateY(${-offset}px)` }}>
        {Array.from({ length: count }, (_, index) => <span key={index} className={errorLines?.has(index + 1) ? "error" : undefined}>{index + 1}</span>)}
      </div>
    </div>
    <textarea id={id} rows={rows} wrap="off" spellCheck={false} value={value} onChange={(event) => onChange(event.target.value)} onScroll={(event) => setOffset(event.currentTarget.scrollTop)} />
  </div>;
}
