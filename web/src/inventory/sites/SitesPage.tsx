import { Fragment, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { inventoryApi, type SiteSort, type SiteView, type SortDirection } from "../../api/inventory";
import { inventoryKeys, invalidateAfterInventoryWrite } from "../queryKeys";
import { useCapabilities, useInventoryDraft } from "../shared";
import { ErrorNotice } from "../ui/ErrorNotice";
import { ImpactReview } from "../ui/ImpactReview";
import { Card, PageHeader } from "../ui/Page";
import { PlaceField, type SitePoint } from "../ui/PlaceField";
import { useDebounced } from "../ui/SitePicker";
import { plural } from "../ui/format";
import { LocationsBrowser } from "./LocationsBrowser";
import { SiteBlocks, SiteGroupPath, blocksValid, sameBlocks } from "./SiteMapFields";
import { ImportDialog, exportMappings, exportSites } from "./SiteTransfer";

const PAGE_SIZE = 50;

const sitePoint = (site: SiteView): SitePoint | null =>
  site.lat != null && site.lon != null ? { lat: site.lat, lon: site.lon } : null;

const samePoint = (a: SitePoint | null, b: SitePoint | null) => a?.lat === b?.lat && a?.lon === b?.lon;

function SiteEditor({ site, onClose }: { site: SiteView; onClose: () => void }) {
  const [name, setName, clearName] = useInventoryDraft(`site:${site.id}:name`, site.name);
  const [location, setLocation, clearLocation] = useInventoryDraft(`site:${site.id}:location`, site.location);
  const [point, setPoint, clearPoint] = useInventoryDraft(`site:${site.id}:point`, sitePoint(site));
  const [siteGroup, setSiteGroup, clearSiteGroup] = useInventoryDraft(`site:${site.id}:site_group`, site.site_group ?? "");
  const [blocks, setBlocks, clearBlocks] = useInventoryDraft(`site:${site.id}:blocks`, site.blocks ?? []);
  const [revision, , clearRevision] = useInventoryDraft(`site:${site.id}:revision`, site.revision);
  const client = useQueryClient();
  const discard = () => { clearName(); clearLocation(); clearPoint(); clearSiteGroup(); clearBlocks(); clearRevision(); };
  const group = siteGroup.trim() || null;
  const trimmed = blocks.map(b => ({ ...b, name: b.name.trim() }));
  const save = useMutation({
    mutationFn: () => inventoryApi.patchSite(site.id, {
      name, location, expected_revision: revision,
      ...(samePoint(point, sitePoint(site)) ? {} : { lat: point?.lat ?? null, lon: point?.lon ?? null }),
      ...(group === (site.site_group ?? null) ? {} : { site_group: group }),
      ...(sameBlocks(trimmed, site.blocks ?? []) ? {} : { blocks: trimmed.length ? trimmed : null }),
    }),
    onSuccess: async () => { await invalidateAfterInventoryWrite(client, "site", { siteId: site.id }); discard(); onClose(); },
  });
  return (
    <form className="inv-form" onSubmit={e => { e.preventDefault(); save.mutate(); }}>
      <h3 className="card-title">Edit {site.code}</h3>
      <div className="inv-form-grid">
        <label className="inv-field"><span>Site name</span><input value={name} onChange={e => setName(e.target.value)} /></label>
        <SiteGroupPath site={site} value={siteGroup} onChange={setSiteGroup} />
        <PlaceField label="Geography" value={location} onChange={setLocation} point={point} onPoint={setPoint} />
      </div>
      <SiteBlocks site={site} value={blocks} onChange={setBlocks} />
      <ErrorNotice error={save.error} />
      <div className="inv-actions">
        <button type="submit" className="primary" disabled={save.isPending || !blocksValid(blocks)}>Save site</button>
        <button type="button" className="secondary" onClick={() => { discard(); onClose(); }}>Discard changes</button>
      </div>
    </form>
  );
}

function SiteCreator({ onClose }: { onClose: () => void }) {
  const client = useQueryClient();
  const [draft, setDraft, clearDraft] = useInventoryDraft("site:create", { code: "", name: "", location: "", point: null as SitePoint | null });
  const create = useMutation({
    mutationFn: () => inventoryApi.createSite({
      code: draft.code, name: draft.name, location: draft.location,
      ...(draft.point ? { lat: draft.point.lat, lon: draft.point.lon } : {}),
    }),
    onSuccess: async () => { await invalidateAfterInventoryWrite(client, "site"); clearDraft(); onClose(); },
  });
  return (
    <Card title="New site">
      <form className="inv-form" onSubmit={e => { e.preventDefault(); create.mutate(); }}>
        <div className="inv-form-grid">
          <label className="inv-field"><span>Site code</span>
            <input required value={draft.code} onChange={e => setDraft({ ...draft, code: e.target.value })} />
          </label>
          <label className="inv-field"><span>Site name</span>
            <input value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} />
          </label>
          <PlaceField label="Geography" value={draft.location} onChange={location => setDraft({ ...draft, location })}
            point={draft.point ?? null} onPoint={point => setDraft({ ...draft, point })} />
        </div>
        <ErrorNotice error={create.error} />
        <div className="inv-actions">
          <button type="submit" className="primary" disabled={create.isPending || !draft.code.trim()}>Create site</button>
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Card>
  );
}

function SortHeader({ label, field, sort, direction, onSort }: { label: string; field: SiteSort; sort: SiteSort; direction: SortDirection; onSort: (field: SiteSort) => void }) {
  const active = sort === field;
  return (
    <th aria-sort={active ? (direction === "desc" ? "descending" : "ascending") : undefined}>
      <button type="button" className={`inv-sort${active ? " on" : ""}`} onClick={() => onSort(field)}>
        {label}{active && <span className="inv-sort-dir">{direction}</span>}
      </button>
    </th>
  );
}

function SitesTable({ canEdit, onShowLocations, initialText, editCode }: {
  canEdit: boolean; onShowLocations: (site: SiteView) => void;
  /** The search text a link opened the page with (`?q=`). */
  initialText: string;
  /** The code of a site whose editor a link asked to open (`?edit=`). */
  editCode: string;
}) {
  const [text, setText] = useState(initialText);
  const [sort, setSort] = useState<SiteSort>("code");
  const [direction, setDirection] = useState<SortDirection>("asc");
  const [offset, setOffset] = useState(0);
  const [editing, setEditing] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<SiteView | null>(null);
  const q = useDebounced(text.trim());
  const params = { q: q || undefined, sort, direction, offset, limit: PAGE_SIZE };
  const page = useQuery({ queryKey: inventoryKeys.sites.search(params), queryFn: () => inventoryApi.searchSites(params), placeholderData: keepPreviousData });
  const sites = page.data?.items ?? [];
  const total = page.data?.total ?? 0;
  // The site map links here to place one site: its editor opens once, when the
  // row is on the page, and closing it does not open it again.
  const [linkedOpened, setLinkedOpened] = useState(false);
  const linked = canEdit && editCode && !linkedOpened ? sites.find(s => s.code === editCode) : undefined;
  if (linked) {
    setLinkedOpened(true);
    setEditing(linked.id);
  }
  const columns = canEdit ? 5 : 4;
  const onSort = (field: SiteSort) => {
    setDirection(sort === field && direction === "asc" ? "desc" : "asc");
    setSort(field); setOffset(0);
  };
  return (
    <div className="inv-tabpanel">
      <div className="inv-listbar">
        <label className="inv-field"><span>Search sites</span>
          <input type="search" value={text} placeholder="Code, name or geography" onChange={e => { setText(e.target.value); setOffset(0); }} />
        </label>
      </div>
      <ErrorNotice error={page.error} retry={() => void page.refetch()} />
      {page.isPending && <p className="hint" role="status">Loading sites</p>}
      {page.data && sites.length === 0 && <div className="results"><p className="tableempty">{q ? "No matching sites" : "No sites"}</p></div>}
      {sites.length > 0 && (
        <div className="results inv-table">
          <table>
            <thead>
              <tr>
                <SortHeader label="Site" field="code" sort={sort} direction={direction} onSort={onSort} />
                <SortHeader label="Name" field="name" sort={sort} direction={direction} onSort={onSort} />
                <th>Geography</th>
                <SortHeader label="Devices" field="devices" sort={sort} direction={direction} onSort={onSort} />
                <th>Reported locations</th>
                {canEdit && <th className="inv-col-actions">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {sites.map(s => (
                <Fragment key={s.id}>
                  <tr>
                    <td className="mono">{s.code}</td>
                    <td>{s.name || <span className="inv-muted">Not set</span>}</td>
                    <td>{s.location || <span className="inv-muted">Not set</span>}</td>
                    <td><Link to={`/inventory/devices?site_id=${encodeURIComponent(s.id)}`}>{plural(s.device_count, "device")}</Link></td>
                    <td>
                      {s.location_count > 0
                        ? <button type="button" className="secondary" onClick={() => onShowLocations(s)}>{plural(s.location_count, "location")}</button>
                        : <span className="inv-muted">None</span>}
                    </td>
                    {canEdit && (
                      <td className="inv-col-actions">
                        <div className="inv-actions">
                          <button type="button" className="secondary" aria-label={`Edit ${s.code}`} disabled={!!editing} onClick={() => setEditing(s.id)}>Edit</button>
                          <button type="button" className="secondary inv-danger" aria-label={`Delete ${s.code}`} onClick={() => setDeleting(s)}>Delete</button>
                        </div>
                      </td>
                    )}
                  </tr>
                  {editing === s.id && <tr><td colSpan={columns + 1}><SiteEditor key={s.id} site={s} onClose={() => setEditing(null)} /></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {total > PAGE_SIZE && (
        <div className="inv-pager">
          <span className="hint">Rows {(offset + 1).toLocaleString()} to {Math.min(offset + PAGE_SIZE, total).toLocaleString()} of {total.toLocaleString()}</span>
          <button type="button" className="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous page</button>
          <button type="button" className="secondary" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next page</button>
        </div>
      )}
      {deleting && <ImpactReview key={deleting.id} request={{ operation: "delete_site", selection: { ids: [deleting.id] } }}
        onCancel={() => setDeleting(null)} onDone={() => setDeleting(null)} />}
    </div>
  );
}

export function InventorySitesPage() {
  const { sites: canEdit } = useCapabilities();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "locations" ? "locations" : "sites";
  const siteFilter = params.get("site_id") ?? "";
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [exportError, setExportError] = useState<unknown>(null);
  const select = (next: "sites" | "locations", siteId = "") => {
    const search = new URLSearchParams();
    if (next === "locations") search.set("tab", "locations");
    if (siteId) search.set("site_id", siteId);
    setParams(search);
  };
  const run = (task: () => Promise<void>) => { setExportError(null); task().catch(setExportError); };
  return (
    <section className="ops-page inv-page">
      <PageHeader title="Sites">
        <details className="inv-menu">
          <summary className="secondary">Export CSV</summary>
          <div className="inv-menu-panel">
            <button type="button" className="secondary" onClick={() => run(exportSites)}>Export sites</button>
            <button type="button" className="secondary" onClick={() => run(exportMappings)}>Export location mappings</button>
          </div>
        </details>
        {canEdit && <button type="button" className="secondary" onClick={() => setImporting(true)}>Import CSV</button>}
        {canEdit && !creating && <button type="button" className="primary" onClick={() => setCreating(true)}>New site</button>}
      </PageHeader>
      <ErrorNotice error={exportError} />
      {creating && <SiteCreator onClose={() => setCreating(false)} />}
      <div className="tabs" role="tablist" aria-label="Site sections">
        <button type="button" role="tab" id="sites-tab-sites" aria-selected={tab === "sites"} aria-controls="sites-panel" className={tab === "sites" ? "on" : ""} onClick={() => select("sites")}>Sites</button>
        <button type="button" role="tab" id="sites-tab-locations" aria-selected={tab === "locations"} aria-controls="sites-panel" className={tab === "locations" ? "on" : ""} onClick={() => select("locations")}>Reported locations</button>
      </div>
      <div id="sites-panel" role="tabpanel" aria-labelledby={`sites-tab-${tab}`}>
        {tab === "sites"
          ? <SitesTable canEdit={canEdit} onShowLocations={s => select("locations", s.id)}
              initialText={params.get("q") ?? ""} editCode={params.get("edit") ?? ""} />
          : <LocationsBrowser key={siteFilter} siteId={siteFilter} initialState={siteFilter ? "all" : "mapped"} canEdit={canEdit} />}
      </div>
      {importing && <ImportDialog onClose={() => setImporting(false)} />}
    </section>
  );
}
