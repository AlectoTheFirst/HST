/** Any typed text is accepted. */

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { exploreApi } from "../api/explore";

function useDebounced<T>(value: T, delay = 200): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return settled;
}

export function ValuePicker({ id, label, property, value, placeholder, required = false, onChange }: {
  id: string; label: string; property: string; value: string; placeholder?: string;
  /** sets aria-required on the input */
  required?: boolean;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const q = useDebounced(value.trim());
  const values = useQuery({
    queryKey: ["explore", "values", label, property, q],
    queryFn: () => exploreApi.values(label, property, q),
    enabled: open,
    staleTime: 60_000,
  });
  const items = values.data?.items ?? [];
  const listId = `${id}-suggestions`;
  const showList = open && (items.length > 0 || values.isError);
  const choose = (next: string) => { onChange(next); setOpen(false); setActive(-1); };
  return (
    <span className="vp">
      <input
        id={id} role="combobox" aria-expanded={showList} aria-controls={listId} aria-autocomplete="list"
        aria-activedescendant={open && active >= 0 ? `${id}-opt-${active}` : undefined}
        aria-required={required || undefined}
        autoComplete="off" spellCheck={false} placeholder={placeholder} value={value}
        onFocus={() => setOpen(true)}
        onBlur={() => { setOpen(false); setActive(-1); }}
        onChange={(e) => { onChange(e.target.value); setOpen(true); setActive(-1); }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" && items.length) { e.preventDefault(); setOpen(true); setActive(Math.min(active + 1, items.length - 1)); }
          else if (e.key === "ArrowUp" && items.length) { e.preventDefault(); setActive(Math.max(active - 1, 0)); }
          // Enter without a highlighted suggestion submits the form.
          else if (e.key === "Enter" && open && active >= 0 && items[active]) { e.preventDefault(); choose(items[active].value); }
          else if (e.key === "Escape" && open) { e.stopPropagation(); setOpen(false); }
        }}
      />
      {showList && (
        <ul id={listId} role="listbox" className="vp-list" aria-label={`Suggested values for ${property}`}>
          {items.map((item, index) => (
            // Mouse-down chooses before the input's blur closes the list.
            <li key={item.value} id={`${id}-opt-${index}`} role="option" aria-selected={index === active}
              className={index === active ? "on" : undefined}
              onMouseDown={(e) => { e.preventDefault(); choose(item.value); }}>
              <span>{item.value}</span>
              {item.id_only && <span className="vp-count">group id</span>}
              {item.count > 1 && <span className="vp-count">{item.count}</span>}
            </li>
          ))}
          {values.isError && (
            <li role="option" aria-selected="false" aria-disabled="true">
              <span className="vp-count">Values not loaded</span>
            </li>
          )}
        </ul>
      )}
    </span>
  );
}
