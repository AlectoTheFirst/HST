import { useState } from "react";
import {
  inventoryApi, MAX_BULK_ROWS,
  type LocationBinding, type LocationBindingResult, type SiteImportResult, type SiteImportRow,
} from "../../api/inventory";
import { useAction } from "../shared";
import { ErrorNotice } from "../ui/ErrorNotice";
import { Modal } from "../ui/Page";
import { plural } from "../ui/format";
import { downloadText, headerIndex, parseCsv, toCsv } from "../ui/csv";
import { BindingSummary } from "./LocationsBrowser";

type Kind = "sites" | "mappings";

function sitesFrom(rows: string[][]): SiteImportRow[] {
  const [header, ...body] = rows;
  const code = headerIndex(header, ["code", "site_code", "site"]);
  if (code < 0) throw new Error("No code column in the header row");
  const name = headerIndex(header, ["name", "site_name"]);
  const location = headerIndex(header, ["location", "geography"]);
  // SITE_CODE_PATTERN of the server.
  const bad = body.findIndex(r => !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(r[code] ?? ""));
  if (bad >= 0) throw new Error(`Row ${bad + 2}: site code ${body[bad][code] ?? ""} not valid`);
  return body.map(r => ({
    code: r[code] ?? "",
    ...(name >= 0 && r[name] ? { name: r[name] } : {}),
    ...(location >= 0 && r[location] ? { location: r[location] } : {}),
  }));
}

function bindingsFrom(rows: string[][]): LocationBinding[] {
  const [header, ...body] = rows;
  const source = headerIndex(header, ["connection", "source_key", "source"]);
  const location = headerIndex(header, ["location_id", "location"]);
  const site = headerIndex(header, ["site_code", "site"]);
  if (source < 0 || location < 0 || site < 0) throw new Error("Missing column connection, location_id or site_code");
  return body.map(r => ({ source_key: r[source] ?? "", location_id: r[location] ?? "", site_code: r[site] || null }));
}

/** Import sites or location mappings from CSV. A dry run checks every row first,
 * and Apply is available when no row is refused. */
export function ImportDialog({ onClose }: { onClose: () => void }) {
  const [kind, setKind] = useState<Kind>("sites");
  const [text, setText] = useState("");
  const [sites, setSites] = useState<{ rows: SiteImportRow[]; check: SiteImportResult } | null>(null);
  const [mappings, setMappings] = useState<{ rows: LocationBinding[]; check: LocationBindingResult } | null>(null);
  const [done, setDone] = useState("");
  const action = useAction(kind === "sites" ? "site" : "location");
  const reset = () => { setSites(null); setMappings(null); setDone(""); action.reset(); };
  const check = () => void action.run(async () => {
    const rows = parseCsv(text);
    if (rows.length < 2) throw new Error("No data rows");
    if (rows.length - 1 > MAX_BULK_ROWS) throw new Error(`${(rows.length - 1).toLocaleString()} rows, limit ${MAX_BULK_ROWS.toLocaleString()} per import`);
    if (kind === "sites") {
      const parsed = sitesFrom(rows);
      setSites({ rows: parsed, check: await inventoryApi.importSites({ sites: parsed, dry_run: true }) });
    } else {
      const parsed = bindingsFrom(rows);
      setMappings({ rows: parsed, check: await inventoryApi.bindLocations({ bindings: parsed, dry_run: true }) });
    }
  });
  const apply = () => void action.run(async () => {
    if (kind === "sites" && sites) {
      const result = await inventoryApi.importSites({ sites: sites.rows });
      if (!result.applied) { setSites({ ...sites, check: result }); return; }
      setDone(`${plural(result.created, "site")} created, ${plural(result.updated, "site")} updated`);
    } else if (mappings) {
      const result = await inventoryApi.bindLocations({ bindings: mappings.rows });
      if (!result.applied) { setMappings({ ...mappings, check: result }); return; }
      setDone(`${plural(result.changed, "location")} changed, ${plural(result.devices_recomputed, "device")} placed again`);
    }
    setSites(null); setMappings(null); setText("");
  });
  const ready = kind === "sites" ? !!sites && sites.check.errors === 0 && sites.check.created + sites.check.updated > 0
    : !!mappings && mappings.check.errors === 0 && mappings.check.changed > 0;
  const checked = kind === "sites" ? !!sites : !!mappings;
  return (
    <Modal label="Import CSV" title="Import CSV" wide locked={action.pending} onClose={onClose} footer={<>
      <button type="button" className="secondary" disabled={action.pending} onClick={onClose}>Close</button>
      {!checked && <button type="button" className="primary" disabled={!text.trim() || action.pending} onClick={check}>Check file</button>}
      {checked && <button type="button" className="primary" disabled={!ready || action.pending} onClick={apply}>Apply</button>}
    </>}>
      <div className="tabs inv-views" role="group" aria-label="Import kind">
        <button type="button" className={kind === "sites" ? "on" : ""} aria-pressed={kind === "sites"} onClick={() => { setKind("sites"); reset(); }}>Sites</button>
        <button type="button" className={kind === "mappings" ? "on" : ""} aria-pressed={kind === "mappings"} onClick={() => { setKind("mappings"); reset(); }}>Location mappings</button>
      </div>
      <label className="inv-field"><span>CSV file</span>
        <input type="file" accept=".csv,text/csv,text/plain" onChange={e => {
          const file = e.target.files?.[0];
          if (file) void file.text().then(value => { setText(value); reset(); });
        }} />
      </label>
      <label className="inv-field"><span>CSV text</span>
        <textarea rows={8} value={text} onChange={e => { setText(e.target.value); reset(); }} placeholder={kind === "sites" ? "code,name,location\nfra,Frankfurt,Germany" : "connection,location_id,site_code\nvco,12,fra"} />
      </label>
      <ErrorNotice error={action.error} />
      {done && <div className="banner ok" role="status"><p>{done}</p></div>}
      {sites && <SiteImportSummary result={sites.check} />}
      {mappings && <BindingSummary result={mappings.check} />}
    </Modal>
  );
}

function SiteImportSummary({ result }: { result: SiteImportResult }) {
  const refused = result.rows.filter(r => r.status === "error");
  return <>
    <div className="inv-stats">
      <div className="inv-stat"><span className="inv-stat-label">Create</span><span className="inv-stat-value">{result.created.toLocaleString()}</span></div>
      <div className="inv-stat"><span className="inv-stat-label">Update</span><span className="inv-stat-value">{result.updated.toLocaleString()}</span></div>
      <div className="inv-stat"><span className="inv-stat-label">Unchanged</span><span className="inv-stat-value">{result.unchanged.toLocaleString()}</span></div>
      <div className="inv-stat"><span className="inv-stat-label">Refused</span><span className="inv-stat-value">{result.errors.toLocaleString()}</span></div>
    </div>
    {refused.length > 0 && <>
      <div className="banner err" role="alert"><p className="sub">{plural(refused.length, "row")} refused</p></div>
      <ul className="inv-list">{refused.slice(0, 50).map(r => <li key={r.index}>Row {r.index + 2}, {r.code}: {r.error}</li>)}</ul>
    </>}
  </>;
}

export async function exportSites() {
  const sites = await inventoryApi.listSites();
  downloadText("sites.csv", toCsv([["code", "name", "location", "devices", "locations"], ...sites.map(s => [s.code, s.name, s.location, s.device_count, s.location_count])]));
}

export async function exportMappings() {
  const locations = await inventoryApi.listLocations();
  downloadText("location-mappings.csv", toCsv([
    ["connection", "location_id", "location_name", "site_code", "devices"],
    ...locations.map(l => [l.source_key, l.location_id, l.name, l.site_code, l.device_count]),
  ]));
}
