import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  inventoryApi, MAX_BULK_ROWS,
  type LocationBinding, type LocationBindingResult, type LocationRow, type LocationSearchQuery, type LocationState,
} from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";
import { useAction } from "../shared";
import { Badge } from "../ui/Badge";
import { ErrorNotice } from "../ui/ErrorNotice";
import { ConfirmDialog } from "../ui/Page";
import { SitePicker, useDebounced } from "../ui/SitePicker";
import { plural } from "../ui/format";

const PAGE_SIZE = 50;
const STATES: ReadonlyArray<readonly [LocationState, string]> = [["all", "All"], ["unmapped", "Unmapped"], ["suggested", "Suggested"], ["mapped", "Mapped"]];
const RULE_LABEL: Record<string, string> = {
  code: "Name matches the site code",
  name: "Name matches the site name",
  location_id: "Location ID matches the site code",
  code_in_name: "Name contains the site code",
};

/** What a bulk write is about to do, after its dry run. */
interface PendingWrite { title: string; bindings: LocationBinding[]; check: LocationBindingResult }

/** Reported locations with filters, paging, bulk mapping and suggested sites.
 * With `connectionId` the list is fixed to one connection. */
export function LocationsBrowser({ connectionId, siteId: initialSite = "", initialState = "all", canEdit }: {
  connectionId?: string; siteId?: string; initialState?: LocationState; canEdit: boolean;
}) {
  const [text, setText] = useState("");
  const [connection, setConnection] = useState(connectionId ?? "");
  const [siteFilter, setSiteFilter] = useState(initialSite);
  const [state, setState] = useState<LocationState>(initialState);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Map<string, LocationRow>>(new Map());
  const [allMatching, setAllMatching] = useState(false);
  const [target, setTarget] = useState("");
  const [pending, setPending] = useState<PendingWrite | null>(null);
  const [done, setDone] = useState<LocationBindingResult | null>(null);
  const action = useAction("location");
  const q = useDebounced(text.trim());
  const filter: LocationSearchQuery = { q: q || undefined, connection_id: connection || undefined, site_id: siteFilter || undefined, state };
  const params = { ...filter, offset, limit: PAGE_SIZE };
  const page = useQuery({ queryKey: inventoryKeys.locations.search(params), queryFn: () => inventoryApi.searchLocations(params), placeholderData: keepPreviousData });
  const items = page.data?.items ?? [];
  const total = page.data?.total ?? 0;
  const counts = page.data?.counts;

  function refilter(edit: () => void) { edit(); setOffset(0); setSelected(new Map()); setAllMatching(false); }
  function toggle(row: LocationRow, on: boolean) {
    const next = new Map(selected);
    if (on) next.set(row.location.id, row); else next.delete(row.location.id);
    setSelected(next); setAllMatching(false);
  }
  const pageSelected = items.length > 0 && items.every(r => selected.has(r.location.id));

  /** Every row the current filter matches, read in pages of 1,000. */
  async function everyMatch(extra: Partial<LocationSearchQuery> = {}): Promise<LocationRow[]> {
    const rows: LocationRow[] = [];
    for (let at = 0; ; at += 1000) {
      const result = await inventoryApi.searchLocations({ ...filter, ...extra, offset: at, limit: 1000 });
      rows.push(...result.items);
      if (rows.length >= result.total || result.items.length === 0) return rows;
      if (rows.length > MAX_BULK_ROWS) throw new Error(`${result.total.toLocaleString()} locations selected, limit ${MAX_BULK_ROWS.toLocaleString()} per request`);
    }
  }
  /** Dry run first. The confirm dialog shows its outcome, and Apply sends the same bindings. */
  async function prepare(title: string, rows: () => Promise<LocationBinding[]>) {
    setDone(null);
    await action.run(async () => {
      const bindings = await rows();
      if (bindings.length > MAX_BULK_ROWS) throw new Error(`${bindings.length.toLocaleString()} locations selected, limit ${MAX_BULK_ROWS.toLocaleString()} per request`);
      return { title, bindings, check: await inventoryApi.bindLocations({ bindings, dry_run: true }) };
    }, setPending);
  }
  const chosenRows = async () => allMatching ? everyMatch() : [...selected.values()];
  const mapSelected = (siteId: string | null) => prepare(
    siteId ? "Map locations to a site" : "Clear location mappings",
    async () => (await chosenRows()).map(r => ({ id: r.location.id, site_id: siteId, expected_revision: r.location.revision })),
  );
  const acceptAll = () => prepare("Accept suggested sites", async () =>
    (await everyMatch({ state: "suggested" })).filter(r => r.suggestion).map(r => ({ id: r.location.id, site_id: r.suggestion!.site_id, expected_revision: r.location.revision })));
  const acceptOne = (row: LocationRow) => {
    setDone(null);
    void action.run(async () => {
      const result = await inventoryApi.bindLocations({ bindings: [{ id: row.location.id, site_id: row.suggestion!.site_id, expected_revision: row.location.revision }] });
      if (!result.applied) throw new Error(result.rows[0]?.error ?? "Location not changed");
      return result;
    }, setDone);
  };
  const apply = () => {
    if (!pending) return;
    void action.run(() => inventoryApi.bindLocations({ bindings: pending.bindings }), result => {
      // A location can change between the dry run and the write. The server then
      // refuses the whole request, and the dialog shows the refused rows.
      if (!result.applied) { setPending({ ...pending, check: result }); return; }
      setPending(null); setDone(result); setSelected(new Map()); setAllMatching(false);
    });
  };
  const selectionCount = allMatching ? total : selected.size;

  return (
    <div className="inv-tabpanel">
      <div className="inv-filters">
        <label className="inv-field"><span>Search locations</span>
          <input type="search" value={text} placeholder="Name, location ID or site code" onChange={e => refilter(() => setText(e.target.value))} />
        </label>
        {!connectionId && (
          <label className="inv-field"><span>Connection</span>
            <select value={connection} onChange={e => refilter(() => setConnection(e.target.value))}>
              <option value="">All connections</option>
              {page.data?.connections.map(c => <option key={c.connection_id} value={c.connection_id}>{c.source_key} ({c.count.toLocaleString()})</option>)}
            </select>
          </label>
        )}
        <SitePicker label="Mapped site" value={siteFilter} emptyLabel="Any site" onChange={id => refilter(() => setSiteFilter(id))} />
      </div>
      <div className="inv-listbar">
        <div className="tabs inv-views" role="group" aria-label="Mapping state">
          {STATES.map(([key, label]) => (
            <button key={key} type="button" className={state === key ? "on" : ""} aria-pressed={state === key} onClick={() => refilter(() => setState(key))}>
              {label}{counts ? ` ${counts[key].toLocaleString()}` : ""}
            </button>
          ))}
        </div>
        {canEdit && !!counts?.suggested && (
          <div className="inv-actions">
            <button type="button" className="secondary" disabled={action.pending} onClick={() => void acceptAll()}>
              Accept {plural(counts.suggested, "suggested site")}
            </button>
          </div>
        )}
      </div>

      <ErrorNotice error={page.error || action.error} retry={page.error ? () => void page.refetch() : undefined} />
      {done && (
        <div className="banner ok" role="status">
          <p>{plural(done.changed, "location")} changed, {plural(done.devices_recomputed, "device")} placed again</p>
        </div>
      )}

      {canEdit && selectionCount > 0 && (
        <div className="editorcard inv-card inv-bulkbar" aria-label="Selected location actions">
          <div className="inv-inline-form">
            <strong>{plural(selectionCount, "location")} selected</strong>
            <SitePicker label="Map to site" value={target} onChange={id => setTarget(id)} />
            <button type="button" className="primary" disabled={!target || action.pending} onClick={() => void mapSelected(target)}>Map to site</button>
            <button type="button" className="secondary" disabled={action.pending} onClick={() => void mapSelected(null)}>Clear mapping</button>
            <button type="button" className="secondary" onClick={() => { setSelected(new Map()); setAllMatching(false); }}>Clear selection</button>
          </div>
          {pageSelected && !allMatching && total > items.length && (
            <p className="hint"><button type="button" className="secondary" onClick={() => setAllMatching(true)}>Select all {total.toLocaleString()} matching locations</button></p>
          )}
        </div>
      )}

      {page.isPending && <p className="hint" role="status">Loading reported locations</p>}
      {page.data && items.length === 0 && (
        <div className="results"><p className="tableempty">{q || state !== "all" || siteFilter ? "No matching locations" : "No reported locations"}</p></div>
      )}
      {items.length > 0 && (
        <div className="results inv-table">
          <table>
            <thead>
              <tr>
                {canEdit && (
                  <th className="inv-col-check">
                    <input type="checkbox" aria-label="Select this page" checked={pageSelected}
                      onChange={e => { const next = new Map(selected); items.forEach(r => e.target.checked ? next.set(r.location.id, r) : next.delete(r.location.id)); setSelected(next); setAllMatching(false); }} />
                  </th>
                )}
                <th>Reported location</th>
                {!connectionId && <th>Connection</th>}
                <th>Devices</th>
                <th>Site</th>
                <th>Suggested site</th>
              </tr>
            </thead>
            <tbody>
              {items.map(row => {
                const l = row.location;
                const name = l.name || l.location_id;
                return (
                  <tr key={l.id} className={selected.has(l.id) || allMatching ? "selected" : undefined}>
                    {canEdit && <td className="inv-col-check"><input type="checkbox" aria-label={`Select ${name}`} checked={allMatching || selected.has(l.id)} onChange={e => toggle(row, e.target.checked)} /></td>}
                    <td><div className="inv-cell-stack"><span>{name}</span><span className="inv-muted mono">{l.location_id}</span></div></td>
                    {!connectionId && <td className="mono">{l.source_key}</td>}
                    <td>{l.device_count.toLocaleString()}</td>
                    <td>{l.site_code ? <span className="mono">{l.site_code}</span> : <span className="inv-muted">Unmapped</span>}</td>
                    <td>
                      {row.suggestion ? (
                        <div className="inv-actions">
                          <Badge tone="ok">{row.suggestion.site_code}</Badge>
                          <span className="inv-muted">{RULE_LABEL[row.suggestion.rule] ?? row.suggestion.rule}</span>
                          {canEdit && <button type="button" className="secondary" aria-label={`Accept ${row.suggestion.site_code} for ${name}`} disabled={action.pending} onClick={() => acceptOne(row)}>Accept</button>}
                        </div>
                      ) : <span className="inv-muted">None</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {page.data && total > PAGE_SIZE && (
        <div className="inv-pager">
          <span className="hint">Rows {(offset + 1).toLocaleString()} to {Math.min(offset + PAGE_SIZE, total).toLocaleString()} of {total.toLocaleString()}</span>
          <button type="button" className="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous page</button>
          <button type="button" className="secondary" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next page</button>
        </div>
      )}

      {pending && (
        <ConfirmDialog label={pending.title} title={pending.title} confirmLabel="Apply" pending={action.pending}
          confirmDisabled={pending.check.errors > 0 || pending.check.changed === 0}
          onConfirm={apply} onCancel={() => setPending(null)}>
          <BindingSummary result={pending.check} />
        </ConfirmDialog>
      )}
    </div>
  );
}

/** The dry-run outcome of a bulk write: counts, then the refused rows. */
export function BindingSummary({ result }: { result: LocationBindingResult }) {
  const refused = result.rows.filter(r => r.status === "error");
  const changes = result.rows.filter(r => r.status === "change").slice(0, 10);
  return <>
    <div className="inv-stats">
      <div className="inv-stat"><span className="inv-stat-label">Change</span><span className="inv-stat-value">{result.changed.toLocaleString()}</span></div>
      <div className="inv-stat"><span className="inv-stat-label">Unchanged</span><span className="inv-stat-value">{result.unchanged.toLocaleString()}</span></div>
      <div className="inv-stat"><span className="inv-stat-label">Refused</span><span className="inv-stat-value">{result.errors.toLocaleString()}</span></div>
    </div>
    {changes.length > 0 && (
      <ul className="inv-list">
        {changes.map(r => <li key={r.index}>{r.name || r.location_id} <span className="inv-muted">{r.site_before ?? "unmapped"} to {r.site_after ?? "unmapped"}</span></li>)}
        {result.changed > changes.length && <li className="inv-muted">{plural(result.changed - changes.length, "more location")}</li>}
      </ul>
    )}
    {refused.length > 0 && <>
      <div className="banner err" role="alert"><p className="sub">{plural(refused.length, "row")} refused</p></div>
      <ul className="inv-list">{refused.slice(0, 50).map(r => <li key={r.index}>Row {r.index + 1}, {r.location_id || "unknown location"}: {r.error}</li>)}</ul>
    </>}
  </>;
}
