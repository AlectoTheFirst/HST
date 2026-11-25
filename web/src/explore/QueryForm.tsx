/** Mount with `key={query.key}` to reset the fields for another query. */

import { useEffect, useState, type FormEvent, useId } from "react";
import type { CannedQuery } from "../api/types";
import { Icon } from "../shell/icons";
import { ValuePicker } from "./ValuePicker";

export function QueryForm({
  query,
  onRun,
  onRunCypher,
  pending,
  initial,
}: {
  query: CannedQuery;
  onRun: (params: Record<string, string>) => void;
  /** The page passes it only for operator+ accounts. */
  onRunCypher?: (cypher: string, params: Record<string, string>) => void;
  pending: boolean;
  /** Starting values for the declared params, keyed by param name. */
  initial?: Record<string, string>;
}) {
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries((query.params ?? []).map((p) => [p.name, initial?.[p.name] ?? ""])),
  );
  // ids from useId: two panes can show the same query
  const formId = useId();
  const [showCypher, setShowCypher] = useState(false);
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(() => query.cypher.trim());

  // the first required field that is empty takes the focus when the form opens
  useEffect(() => {
    const first = (query.params ?? []).find((p) => !p.optional && !(initial?.[p.name] ?? "").trim());
    if (first) document.getElementById(`${formId}-${first.name}`)?.focus();
    // once per form: the page remounts the form for another query
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const canEdit = !!onRunCypher;
  const formTitle = query.section ? `${query.section} ${query.title}` : query.title;
  const edited = editing && text.trim() !== query.cypher.trim();

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (edited && onRunCypher) {
      onRunCypher(text.trim(), values);
      return;
    }
    onRun(values);
  }

  return (
    <form className="editorcard" onSubmit={handleSubmit} aria-label={formTitle}>
      <div className="bar">
        <span className="queryhead">
          <span className="eyebrow">{formTitle}</span>
          {query.description && <span className="querydesc">{query.description}</span>}
        </span>
        <button className="primary" type="submit" disabled={pending}>
          {pending ? "Running" : edited ? "Run edited" : "Run"}
        </button>
      </div>
      {query.params && query.params.length > 0 && (
        <div className="paramrow">
          {query.params.map((p) => (
            <span className="param" key={p.name}>
              <label htmlFor={`${formId}-${p.name}`}>{p.label}</label>
              {p.picker ? (
                <ValuePicker
                  id={`${formId}-${p.name}`}
                  label={p.picker.label}
                  property={p.picker.property}
                  placeholder={p.placeholder}
                  required={!p.optional}
                  value={values[p.name] ?? ""}
                  onChange={(next) => setValues((v) => ({ ...v, [p.name]: next }))}
                />
              ) : (
                <input
                  id={`${formId}-${p.name}`}
                  placeholder={p.placeholder}
                  aria-required={!p.optional || undefined}
                  spellCheck={false}
                  value={values[p.name] ?? ""}
                  onChange={(e) => setValues((v) => ({ ...v, [p.name]: e.target.value }))}
                />
              )}
            </span>
          ))}
        </div>
      )}
      <div className="cypherbar">
        <button
          type="button"
          className="cyphertoggle"
          aria-expanded={showCypher}
          onClick={() => setShowCypher((open) => !open)}
        >
          <span className={"rail-chevron" + (showCypher ? " open" : "")}>
            <Icon name="chevron-right" size={12} />
          </span>
          Cypher
        </button>
        {showCypher && canEdit && !editing && (
          <button type="button" className="cypheredit" onClick={() => setEditing(true)}>
            Edit
          </button>
        )}
        {editing && (
          <button
            type="button"
            className="cypheredit"
            onClick={() => {
              setEditing(false);
              setText(query.cypher.trim());
            }}
          >
            Reset
          </button>
        )}
      </div>
      {showCypher &&
        (editing ? (
          <textarea
            aria-label="Cypher query"
            className="rawedit"
            spellCheck={false}
            rows={Math.min(18, text.split("\n").length + 1)}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        ) : (
          <pre className="rawpre">{query.cypher.trim()}</pre>
        ))}
    </form>
  );
}
