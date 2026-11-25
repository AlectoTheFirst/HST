import { useEffect, useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { inventoryApi, type SiteView } from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";

export function useDebounced<T>(value: T, delay = 250): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return settled;
}

const siteLabel = (site: SiteView) => (site.name && site.name !== site.code ? `${site.name} (${site.code})` : site.code);

/** The picker loads 20 matching sites at a time. */
export function SitePicker({ label, value, onChange, emptyLabel, hideLabel = false, disabled = false }: {
  label: string; value: string; onChange: (id: string, site: SiteView | null) => void;
  emptyLabel?: string; hideLabel?: boolean; disabled?: boolean;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [active, setActive] = useState(0);
  const q = useDebounced(text.trim());
  const results = useQuery({
    queryKey: inventoryKeys.sites.search({ q, limit: 20 }),
    queryFn: () => inventoryApi.searchSites({ q: q || undefined, limit: 20 }),
    enabled: open,
  });
  const selected = useQuery({ queryKey: inventoryKeys.sites.detail(value), queryFn: () => inventoryApi.getSite(value), enabled: !!value });
  const options: Array<{ id: string; label: string; site: SiteView | null }> = [
    ...(emptyLabel !== undefined ? [{ id: "", label: emptyLabel, site: null }] : []),
    ...(results.data?.items ?? []).map(site => ({ id: site.id, label: siteLabel(site), site })),
  ];
  const choose = (option: { id: string; site: SiteView | null }) => {
    onChange(option.id, option.site);
    setOpen(false); setText("");
  };
  const shown = open ? text : value ? (selected.data ? siteLabel(selected.data) : "") : "";
  const listId = `${id}-list`;
  return (
    <div className="inv-field inv-picker">
      <label htmlFor={id} className={hideLabel ? "inv-sr" : undefined}><span className="inv-field-label">{label}</span></label>
      <input id={id} role="combobox" aria-expanded={open} aria-controls={listId} aria-autocomplete="list"
        aria-activedescendant={open && options[active] ? `${id}-opt-${active}` : undefined}
        disabled={disabled} autoComplete="off" value={shown}
        placeholder={value ? "" : emptyLabel ?? "Search sites"}
        onFocus={() => { setOpen(true); setActive(0); }}
        onBlur={() => { setOpen(false); setText(""); }}
        onChange={e => { setText(e.target.value); setOpen(true); setActive(0); }}
        onKeyDown={e => {
          if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive(Math.min(active + 1, options.length - 1)); }
          else if (e.key === "ArrowUp") { e.preventDefault(); setActive(Math.max(active - 1, 0)); }
          else if (e.key === "Enter" && open && options[active]) { e.preventDefault(); choose(options[active]); }
          else if (e.key === "Escape" && open) { e.stopPropagation(); setOpen(false); setText(""); }
        }} />
      {open && (
        <ul id={listId} role="listbox" className="inv-picker-list" aria-label={label}>
          {options.map((option, index) => (
            // The input keeps focus; mouse-down chooses before the input's blur closes the list.
            <li key={option.id || "none"} id={`${id}-opt-${index}`} role="option" aria-selected={index === active}
              className={`${index === active ? "active" : ""}${option.id === value ? " current" : ""}`}
              onMouseDown={e => { e.preventDefault(); choose(option); }}>
              {option.label}
            </li>
          ))}
          {results.isPending && <li className="inv-picker-note" role="option" aria-selected="false" aria-disabled="true">Searching</li>}
          {results.isError && <li className="inv-picker-note" role="option" aria-selected="false" aria-disabled="true">Sites not loaded</li>}
          {results.data && results.data.items.length === 0 && <li className="inv-picker-note" role="option" aria-selected="false" aria-disabled="true">No matching sites</li>}
          {results.data && results.data.total > results.data.items.length && (
            <li className="inv-picker-note" role="option" aria-selected="false" aria-disabled="true">{results.data.total - results.data.items.length} more</li>
          )}
        </ul>
      )}
    </div>
  );
}
