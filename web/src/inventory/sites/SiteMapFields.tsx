import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { inventoryApi, MAX_PAGE_LIMIT, type DevicePage, type DeviceSummary, type SiteView } from "../../api/inventory";
import type { SiteBlock } from "../../api/types";
import { inventoryKeys } from "../queryKeys";
import { ErrorNotice } from "../ui/ErrorNotice";

function siteGroupsBesides(sites: SiteView[], code: string): string[] {
  const paths = sites.filter(s => s.code !== code).map(s => s.site_group ?? "");
  return [...new Set(paths.filter(Boolean))].sort();
}

/** The site group the site sits in, a path from the top. The field offers
 * the paths other sites use, and the server normalizes what is typed. */
export function SiteGroupPath({ site, value, onChange }: {
  site: SiteView; value: string; onChange: (path: string) => void;
}) {
  const id = useId();
  const [used, setUsed] = useState(false);
  const sites = useQuery({ queryKey: inventoryKeys.sites.list(), queryFn: inventoryApi.listSites, enabled: used });
  const paths = siteGroupsBesides(sites.data ?? [], site.code);
  return (
    <div className="inv-field">
      <label htmlFor={id}><span className="inv-field-label">Site group</span></label>
      <input id={id} value={value} list={paths.length ? `${id}-paths` : undefined} autoComplete="off"
        placeholder="Region / Metro"
        onFocus={() => setUsed(true)} onChange={e => onChange(e.target.value)} />
      {paths.length > 0 && (
        <datalist id={`${id}-paths`}>
          {paths.map(path => <option key={path} value={path} />)}
        </datalist>
      )}
    </div>
  );
}

function describeBlock(block: SiteBlock): string {
  const count = `${block.devices.length} device${block.devices.length === 1 ? "" : "s"}`;
  return `${block.name} (${block.zone ? `${block.zone}, ` : ""}${count})`;
}

/** Every block has a name, and no two share one in any case. */
export function blocksValid(blocks: SiteBlock[]): boolean {
  const names = blocks.map(b => b.name.trim().toLowerCase());
  return names.every(Boolean) && new Set(names).size === names.length;
}

export function sameBlocks(a: SiteBlock[], b: SiteBlock[]): boolean {
  return a.length === b.length && a.every((block, i) =>
    block.name === b[i].name && (block.zone ?? null) === (b[i].zone ?? null)
    && block.devices.length === b[i].devices.length && block.devices.every((uid, j) => uid === b[i].devices[j]));
}

async function devicesAt(siteId: string): Promise<DeviceSummary[]> {
  const devices: DeviceSummary[] = [];
  let cursor: string | null = null;
  do {
    const page: DevicePage = await inventoryApi.listDevices({ site_id: [siteId], limit: MAX_PAGE_LIMIT, cursor });
    devices.push(...page.items);
    cursor = page.next_cursor;
  } while (cursor);
  return devices;
}

/** The named blocks of the site. A device is in at most one block of its
 * site, so a device another block holds is shown as taken. The checklist is
 * the devices placed at this site, plus any uid a block holds that is not
 * placed here, so it can be taken out. */
export function SiteBlocks({ site, value, onChange }: {
  site: SiteView; value: SiteBlock[]; onChange: (blocks: SiteBlock[]) => void;
}) {
  const [open, setOpen] = useState(() => !blocksValid(value));
  const devices = useQuery({ queryKey: inventoryKeys.devices.atSite(site.id), queryFn: () => devicesAt(site.id), enabled: open });

  if (!open) {
    return (
      <div className="hint">
        {value.length ? `Named blocks: ${value.map(describeBlock).join(", ")}` : "No named blocks"}{" "}
        <button type="button" className="secondary" onClick={() => setOpen(true)}>
          {value.length ? "Edit named blocks" : "Add named blocks"}
        </button>
      </div>
    );
  }

  const placed = devices.data ?? [];
  const hostname = new Map(placed.map(d => [d.graph_uid, d.hostname] as const));
  const here = placed.map(d => d.graph_uid);
  const elsewhere = [...new Set(value.flatMap(b => b.devices))].filter(uid => !here.includes(uid));
  const choices = [...here, ...elsewhere];
  const owner = new Map(value.flatMap((b, i) => b.devices.map(uid => [uid, i] as const)));

  const update = (i: number, change: Partial<SiteBlock>) =>
    onChange(value.map((block, j) => (j === i ? { ...block, ...change } : block)));
  const toggle = (i: number, uid: string, on: boolean) => {
    const held = new Set(value[i].devices);
    if (on) held.add(uid);
    else held.delete(uid);
    update(i, { devices: choices.filter(c => held.has(c)) });
  };

  return (
    <fieldset>
      <legend>Named blocks at {site.code}</legend>
      <ErrorNotice error={devices.error} retry={() => void devices.refetch()} />
      {devices.isPending && <p className="hint" role="status">Loading devices at {site.code}</p>}
      {value.length === 0 && <p className="hint">No named blocks</p>}
      {value.map((block, i) => (
        <fieldset key={i}>
          <legend>Block {i + 1}</legend>
          <div className="inv-form-grid">
            <label className="inv-field"><span>Block name</span>
              <input value={block.name} maxLength={40} onChange={e => update(i, { name: e.target.value })} />
            </label>
            <label className="inv-field"><span>Zone</span>
              <select value={block.zone ?? ""} onChange={e => update(i, { zone: (e.target.value || null) as SiteBlock["zone"] })}>
                <option value="">None</option>
                <option value="internal">Internal</option>
                <option value="external">External</option>
                <option value="internet">Internet</option>
              </select>
            </label>
            <div className="inv-actions">
              <button type="button" className="secondary inv-danger" onClick={() => onChange(value.filter((_, j) => j !== i))}>Remove block</button>
            </div>
          </div>
          {devices.data && choices.length === 0 && <p className="hint">No devices at {site.code}</p>}
          {choices.length > 0 && (
            <div className="inv-block-devices">
              {choices.map(uid => {
                const at = owner.get(uid);
                const holder = at !== undefined && at !== i ? value[at] : undefined;
                return (
                  <label className="inv-check" key={uid}>
                    <input type="checkbox" checked={block.devices.includes(uid)} disabled={holder !== undefined}
                      onChange={e => toggle(i, uid, e.target.checked)} />
                    {hostname.get(uid) || uid}
                    {holder ? ` (in ${holder.name.trim() || "another block"})` : ""}
                    {here.includes(uid) || !devices.data ? "" : " (not at this site)"}
                  </label>
                );
              })}
            </div>
          )}
        </fieldset>
      ))}
      <div className="inv-actions">
        <button type="button" className="secondary" onClick={() => onChange([...value, { name: "", zone: null, devices: [] }])}>Add block</button>
      </div>
    </fieldset>
  );
}
