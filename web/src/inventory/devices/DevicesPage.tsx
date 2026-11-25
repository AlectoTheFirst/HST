import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  inventoryApi, COLLECTION_STATES, PLACEMENT_STATES, LIFECYCLES, SORT_FIELDS,
  type DeviceListQuery, type DeviceSummary, type Generation, type PlacementMode, type PreviewRequest, type Selection, type SortField,
} from "../../api/inventory";
import { inventoryKeys, invalidateAfterInventoryWrite } from "../queryKeys";
import { useCapabilities, deviceLink } from "../shared";
import { SavedViews } from "../views/SavedViews";
import { Badge, StateBadge } from "../ui/Badge";
import { ErrorNotice } from "../ui/ErrorNotice";
import { ImpactReview } from "../ui/ImpactReview";
import { Card, PageHeader } from "../ui/Page";
import { SitePicker } from "../ui/SitePicker";
import { COLLECTION_STATE, LIFECYCLE, OBSERVATION, PLACEMENT_STATE, SORT_LABEL, formatTime, plural, type StateMap } from "../ui/format";
import { DeviceDetail } from "./DeviceDetail";

const PAGE_SIZE = 50;
const COLUMNS = ["platform", "site", "collection", "last_success", "connections"] as const;
type Column = typeof COLUMNS[number];
const COLUMN_LABEL: Record<Column, string> = { platform: "Platform", site: "Site", collection: "Collection", last_success: "Last success", connections: "Connections" };
const COLUMN_SORT: Partial<Record<Column, SortField>> = { platform: "platform", site: "site", collection: "collection_state", last_success: "last_success" };
const FILTER_KEYS = ["q", "site_id", "connection_id", "platform", "collection_state", "placement_state", "lifecycle"];
const BUILT_IN_VIEWS: ReadonlyArray<readonly [string, string]> = [
  ["All devices", ""],
  ["Unplaced", "placement_state=unplaced"],
  ["Collection issues", "collection_state=failed&collection_state=partial&collection_state=stale"],
  ["Archived", "lifecycle=archived"],
];
/** Placement states that need attention show as a badge. The others show as plain text. */
const NOTABLE_PLACEMENT = new Set(["conflict", "stale", "pending", "unplaced"]);

export function deviceQuery(params: URLSearchParams): DeviceListQuery {
  return { q: params.get("q"), site_id: params.getAll("site_id"), connection_id: params.getAll("connection_id"), platform: params.getAll("platform"), collection_state: params.getAll("collection_state").filter((x): x is typeof COLLECTION_STATES[number] => COLLECTION_STATES.includes(x as typeof COLLECTION_STATES[number])), placement_state: params.getAll("placement_state").filter((x): x is typeof PLACEMENT_STATES[number] => PLACEMENT_STATES.includes(x as typeof PLACEMENT_STATES[number])), lifecycle: params.getAll("lifecycle").filter((x): x is typeof LIFECYCLES[number] => LIFECYCLES.includes(x as typeof LIFECYCLES[number])), sort: SORT_FIELDS.find(x => x === params.get("sort")) ?? "name", direction: params.get("direction") === "desc" ? "desc" : "asc", cursor: params.get("cursor"), view_id: params.get("view_id"), limit: PAGE_SIZE };
}

/** The filter part of a search string, in a stable order. */
function filterSignature(params: URLSearchParams): string {
  return FILTER_KEYS.flatMap(key => params.getAll(key).filter(Boolean).sort().map(value => `${key}=${value}`)).join("&");
}

export function InventoryDevicesPage() {
  const { id } = useParams();
  const location = useLocation();
  const [params] = useSearchParams();
  const drawer = !!id && !!location.state?.inventoryBackground;
  if (id && !drawer) {
    return (
      <section className="ops-page inv-page">
        <Link className="inv-back" to={`/inventory/devices?${params.toString()}`}>Back to devices</Link>
        <DeviceDetail id={id} />
      </section>
    );
  }
  return <DeviceList drawerId={drawer ? id : undefined} />;
}

function DeviceList({ drawerId }: { drawerId?: string }) {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const caps = useCapabilities();
  const client = useQueryClient();
  const dialog = useRef<HTMLDialogElement>(null);
  const lastOpened = useRef<string | null>(null);
  const scrollBefore = useRef(0);
  const query = deviceQuery(params);
  const [mode, setMode] = useState<PlacementMode>("auto");
  const [site, setSite] = useState("");
  const [review, setReview] = useState<PreviewRequest | null>(null);
  const [previousCursors, setPreviousCursors] = useState<string[]>([]);
  const [selectionGeneration, setSelectionGeneration] = useState<{ generation: Generation; filter: string } | null>(null);
  const selectionFilter = JSON.stringify(query);
  const all = selectionGeneration?.filter === selectionFilter ? selectionGeneration.generation : null;
  function setAll(value: Generation | null) { setSelectionGeneration(value ? { generation: value, filter: selectionFilter } : null); }
  const [chosenTargets, setChosenTargets] = useState<string[]>([]);
  const selected = params.getAll("selected");
  const columns = params.getAll("column");
  const shown = COLUMNS.filter(c => !params.has("column") || columns.includes(c));

  const page = useQuery({ queryKey: inventoryKeys.devices.list(query), queryFn: () => inventoryApi.listDevices(query), retry: false });
  const connections = useQuery({ queryKey: inventoryKeys.connections.list({}), queryFn: () => inventoryApi.listConnections(), enabled: caps.read });
  const items = page.data?.items ?? [];
  const chosenDevices = items.filter(d => selected.includes(d.id));
  const targetMap = new Map(chosenDevices.flatMap(d => d.connections).map(t => [t.target_id, t]));
  const selection: Selection = all
    ? { filter: { ...query, cursor: undefined }, snapshot_key: all.snapshot_key, intent_generation: all.intent_generation }
    : { ids: selected, snapshot_key: page.data?.generation.snapshot_key, intent_generation: page.data?.generation.intent_generation };

  const collect = useMutation({
    mutationFn: async () => {
      const remaining = new Set(chosenTargets);
      const responses = [];
      for (const d of chosenDevices) {
        const ids = d.connections.map(c => c.target_id).filter(t => remaining.has(t));
        if (ids.length) {
          responses.push(await inventoryApi.collectDevice(d.id, { target_ids: ids }));
          ids.forEach(t => remaining.delete(t));
        }
      }
      return responses;
    },
    onSuccess: () => invalidateAfterInventoryWrite(client, "collect"),
  });

  useEffect(() => {
    if (drawerId && dialog.current && !dialog.current.open) {
      lastOpened.current = drawerId;
      scrollBefore.current = window.scrollY;
      dialog.current.showModal();
    }
    if (!drawerId && lastOpened.current) {
      document.getElementById(`device-${lastOpened.current}`)?.focus({ preventScroll: true });
      window.scrollTo(0, scrollBefore.current);
      lastOpened.current = null;
    }
  }, [drawerId]);

  function resetSelection() { setAll(null); setChosenTargets([]); setPreviousCursors([]); }
  function update(edit: (next: URLSearchParams) => void, replace = false) {
    const next = new URLSearchParams(params);
    next.delete("cursor"); next.delete("selected"); next.delete("view_id");
    edit(next);
    resetSelection();
    setParams(next, { replace });
  }
  function change(key: string, value: string, replace = false) {
    update(next => { next.delete(key); if (value) next.set(key, value); }, replace);
  }
  function sortBy(field: SortField) {
    update(next => {
      const direction = query.sort === field && query.direction === "asc" ? "desc" : "asc";
      next.set("sort", field); next.set("direction", direction);
    });
  }
  function updateSelection(ids: string[]) {
    const next = new URLSearchParams(params);
    next.delete("selected"); ids.forEach(x => next.append("selected", x));
    setParams(next, { replace: true }); setAll(null); setChosenTargets([]);
  }
  function goToCursor(cursor: string | null, stack: string[]) {
    const next = new URLSearchParams(params);
    if (cursor) next.set("cursor", cursor); else next.delete("cursor");
    next.delete("selected");
    setAll(null); setChosenTargets([]); setPreviousCursors(stack);
    setParams(next);
  }

  const signature = filterSignature(params);
  const filtered = signature !== "";
  const pageNumber = !query.cursor ? 1 : previousCursors.length ? previousCursors.length + 1 : null;
  const platforms = [...new Set(items.map(d => d.platform).filter(Boolean))].sort();

  return (
    <section className="ops-page inv-page" aria-labelledby="inv-devices-title">
      <PageHeader title="Devices" meta={page.data && <>
        <span>Snapshot <span className="mono">{page.data.generation.snapshot_key ?? "none"}</span></span>
        {page.data.generation.inventory_sync_pending && <Badge tone="warn">Publication pending</Badge>}
      </>}>
        {caps.read && <Link className="secondary" to="/inventory/connections">Connections and pending targets</Link>}
      </PageHeader>

      <div className="tabs inv-views" role="group" aria-label="Built-in views">
        {BUILT_IN_VIEWS.map(([label, search]) => (
          <button key={label} type="button" className={signature === filterSignature(new URLSearchParams(search)) ? "on" : ""}
            aria-pressed={signature === filterSignature(new URLSearchParams(search))}
            onClick={() => { resetSelection(); setParams(new URLSearchParams(search)); }}>{label}</button>
        ))}
      </div>

      <div className="inv-filters">
        <SearchField value={params.get("q") ?? ""} onCommit={value => change("q", value, true)} />
        <label className="inv-field"><span>Platform</span>
          <input list="inv-platforms" value={params.get("platform") ?? ""} onChange={e => change("platform", e.target.value, true)} />
          <datalist id="inv-platforms">{platforms.map(p => <option key={p} value={p} />)}</datalist>
        </label>
        <SitePicker label="Site" value={params.get("site_id") ?? ""} emptyLabel="All sites" onChange={id => change("site_id", id)} />
        <StateFilter label="Collection state" name="collection_state" map={COLLECTION_STATE} params={params} onChange={change} />
        <StateFilter label="Placement state" name="placement_state" map={PLACEMENT_STATE} params={params} onChange={change} />
        <StateFilter label="Lifecycle" name="lifecycle" map={LIFECYCLE} params={params} onChange={change} />
        {caps.read ? (
          <label className="inv-field"><span>Connection</span>
            <select value={params.get("connection_id") ?? ""} onChange={e => change("connection_id", e.target.value)}>
              <option value="">All connections</option>
              {connections.data?.map(c => <option key={c.id} value={c.id}>{c.display_name}</option>)}
            </select>
          </label>
        ) : params.has("connection_id") && (
          <div className="inv-field"><span className="inv-field-label">Connection</span>
            <button type="button" className="secondary" onClick={() => change("connection_id", "")}>Remove connection filter</button>
          </div>
        )}
      </div>

      <div className="inv-listbar">
        {page.data && pageNumber && <span className="hint">Page {pageNumber}</span>}
        {filtered && <button type="button" className="secondary" onClick={() => update(next => FILTER_KEYS.forEach(key => next.delete(key)))}>Clear filters</button>}
        {(caps.sites || caps.lifecycle) && page.data && items.length > 0 && (
          <label className="inv-check">
            <input type="checkbox" checked={!!all} onChange={e => { setAll(e.target.checked ? page.data!.generation : null); setChosenTargets([]); }} />
            Select all matching devices
            <span className="inv-muted">Up to 1,000 devices</span>
          </label>
        )}
        <div className="inv-actions">
          <details className="inv-menu">
            <summary className="secondary">Columns</summary>
            <div className="inv-menu-panel">
              {COLUMNS.map(c => (
                <label className="inv-check" key={c}>
                  <input type="checkbox" checked={shown.includes(c)} onChange={() => {
                    const next = new URLSearchParams(params);
                    next.delete("column");
                    const updated = shown.includes(c) ? shown.filter(x => x !== c) : [...shown, c];
                    (updated.length ? updated : [""]).forEach(x => next.append("column", x));
                    setParams(next, { replace: true });
                  }} />
                  {COLUMN_LABEL[c]}
                </label>
              ))}
            </div>
          </details>
          <SavedViews query={query} columns={shown} onSelect={v => {
            const next = new URLSearchParams();
            Object.entries(v.filter).forEach(([k, value]) => {
              if (k === "version" || value == null) return;
              if (Array.isArray(value)) value.forEach(x => next.append(k, x)); else next.set(k, String(value));
            });
            next.set("sort", v.sort); next.set("direction", v.direction); next.set("view_id", v.id);
            (v.columns.length ? v.columns : [""]).forEach(c => next.append("column", c));
            resetSelection(); setParams(next);
          }} />
        </div>
      </div>

      <ErrorNotice error={page.error} retry={() => void page.refetch()} />
      {page.error && (
        <div><button type="button" className="secondary" onClick={() => {
          const next = new URLSearchParams(params);
          next.delete("cursor"); next.delete("selected");
          resetSelection(); setParams(next); void page.refetch();
        }}>Restart list and selection</button></div>
      )}
      {page.isPending && <p className="hint" role="status">Loading devices</p>}

      {page.data && (items.length === 0 ? (
        <div className="results"><p className="tableempty">{filtered ? "No matching devices" : "No devices"}</p></div>
      ) : (
        <div className="results inv-table">
          <table>
            <thead>
              <tr>
                <th className="inv-col-check">
                  <input aria-label="Select this page" type="checkbox" checked={items.every(d => selected.includes(d.id))}
                    onChange={e => updateSelection(e.target.checked ? items.map(d => d.id) : [])} />
                </th>
                <SortHeader label="Name" field="name" query={query} onSort={sortBy} />
                {shown.map(c => COLUMN_SORT[c]
                  ? <SortHeader key={c} label={COLUMN_LABEL[c]} field={COLUMN_SORT[c]!} query={query} onSort={sortBy} />
                  : <th key={c}>{COLUMN_LABEL[c]}</th>)}
              </tr>
            </thead>
            <tbody>
              {items.map(d => (
                <DeviceRow key={d.id} device={d} shown={shown} params={params} selected={selected.includes(d.id)}
                  onSelect={checked => updateSelection(checked ? [...selected, d.id] : selected.filter(x => x !== d.id))} />
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {page.data && (query.cursor || page.data.next_cursor) && (
        <div className="inv-pager">
          <button type="button" className="secondary" disabled={!query.cursor} onClick={() => goToCursor(null, [])}>First page</button>
          <button type="button" className="secondary" disabled={!previousCursors.length} onClick={() => goToCursor(previousCursors.at(-1) || null, previousCursors.slice(0, -1))}>Previous page</button>
          <button type="button" className="secondary" disabled={!page.data.next_cursor} onClick={() => goToCursor(page.data!.next_cursor, [...previousCursors, query.cursor ?? ""])}>Next page</button>
        </div>
      )}

      {page.data && (selected.length > 0 || all) && (
        <Card className="inv-selection" label="Selected device actions"
          title={all ? "All matching devices" : `${plural(selected.length, "device")} selected`}
          actions={<button type="button" className="secondary" onClick={() => updateSelection([])}>Clear selection</button>}>
          <div className="inv-selection-groups">
            {caps.sites && (
              <div className="inv-selection-group">
                <h3 className="eyebrow">Placement</h3>
                <label className="inv-field"><span>Placement mode</span>
                  <select value={mode} onChange={e => setMode(e.target.value as PlacementMode)}>
                    <option value="auto">Automatic</option>
                    <option value="assigned">Assign site</option>
                    <option value="unplaced">Unplaced</option>
                  </select>
                </label>
                {mode === "assigned" && (
                  <SitePicker label="Destination site" value={site} onChange={id => setSite(id)} />
                )}
                <div className="inv-actions">
                  <button type="button" className="primary" disabled={mode === "assigned" && !site}
                    onClick={() => setReview({ operation: "place_devices", selection, change: { mode, site_id: mode === "assigned" ? site : null } })}>Preview placement</button>
                </div>
              </div>
            )}
            {caps.lifecycle && (
              <div className="inv-selection-group">
                <h3 className="eyebrow">Lifecycle</h3>
                <div className="inv-actions">
                  <button type="button" className="secondary" onClick={() => setReview({ operation: "archive_devices", selection })}>Preview archive</button>
                  <button type="button" className="secondary" onClick={() => setReview({ operation: "restore_devices", selection })}>Preview restore</button>
                </div>
              </div>
            )}
            {(caps.read || caps.write) && (all ? (
              <div className="inv-selection-group">
                <h3 className="eyebrow">Collection targets</h3>
              </div>
            ) : (
              <div className="inv-selection-group">
                <h3 className="eyebrow">Collection targets</h3>
                <div className="inv-target-list">
                  {Array.from(targetMap.values()).map(t => (
                    <label className="inv-check" key={t.target_id}>
                      <input type="checkbox" checked={chosenTargets.includes(t.target_id)}
                        onChange={e => setChosenTargets(e.target.checked ? [...chosenTargets, t.target_id] : chosenTargets.filter(x => x !== t.target_id))} />
                      {t.display_name || t.source_key} on {t.target_host || "controller"}
                    </label>
                  ))}
                  {targetMap.size === 0 && <p className="hint">No targets</p>}
                </div>
                <div className="inv-actions">
                  {caps.read && <button type="button" className="secondary" disabled={!chosenTargets.length || collect.isPending} onClick={() => collect.mutate()}>Collect chosen targets</button>}
                  {caps.write && chosenTargets.length > 0 && (
                    <Link className="secondary" to={`/inventory/connections/profiles?${new URLSearchParams(chosenTargets.map(t => ["target_id", t])).toString()}`}>Review profile assignment</Link>
                  )}
                </div>
                <ErrorNotice error={collect.error} />
                {collect.data && (
                  <div className="banner ok" role="status">
                    {collect.data.map((r, n) => <div key={n}>
                      <p>{plural(r.jobs.length, "job")} queued</p>
                      {r.skipped.map(t => <p key={t.target_id}>Skipped {t.target_id}: {t.reason}</p>)}
                    </div>)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {review && <ImpactReview key={JSON.stringify(review)} request={review} onCancel={() => setReview(null)}
        onDone={() => { setReview(null); updateSelection([]); setAll(null); }} />}

      {drawerId && (
        <dialog ref={dialog} className="inv-drawer" aria-label="Device details" onCancel={e => { e.preventDefault(); navigate(-1); }}>
          <div className="drawer-head">
            <span className="eyebrow">Device details</span>
            <div className="drawer-headactions">
              <Link className="secondary" to={deviceLink(drawerId)}>Open full page</Link>
              <button type="button" className="secondary" aria-label="Close device details" onClick={() => navigate(-1)}>Close</button>
            </div>
          </div>
          <div className="inv-drawer-body"><DeviceDetail id={drawerId} /></div>
        </dialog>
      )}
    </section>
  );
}

/** Search commits to the URL after typing pauses, as one replaced history entry. */
function SearchField({ value, onCommit }: { value: string; onCommit: (value: string) => void }) {
  const [text, setText] = useState(value);
  const [synced, setSynced] = useState(value);
  if (value !== synced) { setSynced(value); setText(value); }
  const commit = useRef(onCommit);
  useEffect(() => { commit.current = onCommit; });
  useEffect(() => {
    if (text === value) return;
    const timer = window.setTimeout(() => commit.current(text), 300);
    return () => window.clearTimeout(timer);
  }, [text, value]);
  return (
    <label className="inv-field"><span>Search devices</span>
      <input type="search" placeholder="Hostname, address or identity" value={text} onChange={e => setText(e.target.value)} />
    </label>
  );
}

function StateFilter<K extends string>({ label, name, map, params, onChange }: {
  label: string; name: string; map: StateMap<K>; params: URLSearchParams; onChange: (key: string, value: string) => void;
}) {
  const values = params.getAll(name);
  return (
    <label className="inv-field"><span>{label}</span>
      <select value={values.length > 1 ? "__several" : values[0] ?? ""} onChange={e => onChange(name, e.target.value)}>
        <option value="">Any</option>
        {values.length > 1 && <option value="__several" disabled>{values.length} selected</option>}
        {(Object.keys(map) as K[]).map(value => <option key={value} value={value}>{map[value].label}</option>)}
      </select>
    </label>
  );
}

function SortHeader({ label, field, query, onSort }: { label: string; field: SortField; query: DeviceListQuery; onSort: (field: SortField) => void }) {
  const active = query.sort === field;
  return (
    <th aria-sort={active ? (query.direction === "desc" ? "descending" : "ascending") : undefined}>
      <button type="button" className={`inv-sort${active ? " on" : ""}`} onClick={() => onSort(field)}>
        {label}{active && <span className="inv-sort-dir">{query.direction === "desc" ? "desc" : "asc"}</span>}
        <span className="inv-sr">, sort by {SORT_LABEL[field].toLowerCase()}</span>
      </button>
    </th>
  );
}

function DeviceRow({ device: d, shown, params, selected, onSelect }: {
  device: DeviceSummary; shown: readonly Column[]; params: URLSearchParams; selected: boolean; onSelect: (checked: boolean) => void;
}) {
  const name = d.hostname || d.graph_uid;
  return (
    <tr className={selected ? "selected" : undefined}>
      <td className="inv-col-check"><input type="checkbox" aria-label={`Select ${d.hostname || d.id}`} checked={selected} onChange={e => onSelect(e.target.checked)} /></td>
      <td>
        <div className="inv-cell-stack">
          <Link id={`device-${d.id}`} className="inv-row-name" to={`/inventory/devices/${encodeURIComponent(d.id)}?${params.toString()}`}
            state={{ inventoryBackground: `/inventory/devices?${params.toString()}` }}>{name}</Link>
          {d.management_address && <span className="inv-muted mono">{d.management_address}</span>}
          {d.lifecycle !== "active" && <StateBadge map={LIFECYCLE} value={d.lifecycle} />}
        </div>
      </td>
      {shown.includes("platform") && <td>{d.platform || <span className="inv-muted">Unknown</span>}</td>}
      {shown.includes("site") && (
        <td>
          {d.placement_state === "unplaced" ? <span className="inv-muted">Unplaced</span> : (
            <div className="inv-cell-stack">
              <span>{d.site_code ?? "No site"}</span>
              {NOTABLE_PLACEMENT.has(d.placement_state)
                ? <StateBadge map={PLACEMENT_STATE} value={d.placement_state} />
                : <span className="inv-muted">{PLACEMENT_STATE[d.placement_state]?.label ?? d.placement_state}</span>}
            </div>
          )}
        </td>
      )}
      {shown.includes("collection") && <td><StateBadge map={COLLECTION_STATE} value={d.collection_state} /></td>}
      {shown.includes("last_success") && <td>{formatTime(d.last_success_at)}</td>}
      {shown.includes("connections") && (
        <td>
          <div className="inv-cell-stack">
            {d.connections.map(c => (
              <span key={c.target_id} className="inv-actions">
                {c.display_name || c.source_key}
                <StateBadge map={OBSERVATION} value={c.observation_state} />
                {c.authority === "partial" && <Badge tone="warn">Partial</Badge>}
              </span>
            ))}
          </div>
        </td>
      )}
    </tr>
  );
}
