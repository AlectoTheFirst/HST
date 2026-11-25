/**
 * Sites: geography, and which device sits where.
 */

import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { useAuth, atLeast } from "../auth";
import { SITES_GRAPH_KEY } from "../inventory/queryKeys";
import { metroOf } from "./metros";
import type {
  ReportedLocation,
  ReportedLocationsResponse,
  Site,
  SiteDevice,
  SiteDevicesResponse,
  SiteRelease,
  SitesResponse,
  Source,
  SourcesResponse,
} from "../api/types";

export default function SitesPage() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canEdit = !!user && atLeast(user.role, "operator");
  const canEditDefaults = !!user?.permissions.includes("sources.write");

  const [selected, setSelected] = useState<string | null>(null);
  const [released, setReleased] = useState<SiteRelease | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [draft, setDraft] = useState({ code: "", name: "", location: "" });

  const sites = useQuery({
    queryKey: ["sites"],
    queryFn: () => api<SitesResponse>("/sites"),
  });
  const devices = useQuery({
    queryKey: ["site-devices"],
    queryFn: () => api<SiteDevicesResponse>("/sites/devices"),
  });

  function refresh() {
    queryClient.invalidateQueries({ queryKey: ["sites"] });
    queryClient.invalidateQueries({ queryKey: ["site-devices"] });
    queryClient.invalidateQueries({ queryKey: SITES_GRAPH_KEY });
  }

  const create = useMutation({
    mutationFn: (body: { code: string; name: string; location: string; params?: Site["params"] }) => api<Site>("/sites", { method: "POST", body }),
    onSuccess: () => {
      setDraft({ code: "", name: "", location: "" });
      refresh();
    },
  });

  const patch = useMutation({
    mutationFn: ({ code, ...body }: { code: string; name?: string; location?: string; params?: Site["params"] }) =>
      api<Site>(`/sites/${encodeURIComponent(code)}`, { method: "PATCH", body }),
    onSuccess: refresh,
  });

  const remove = useMutation({
    mutationFn: (code: string) => api<SiteRelease>(`/sites/${encodeURIComponent(code)}`, { method: "DELETE" }),
    onSuccess: (released) => {
      setReleased(released);
      setSelected(null);
      refresh();
    },
  });

  const assign = useMutation({
    mutationFn: (body: { device_uid: string; site: string | null }) =>
      api<unknown>("/sites/assign", { method: "POST", body }),
    onSuccess: refresh,
  });

  function handleCreate(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!draft.code.trim()) return;
    create.mutate(draft);
  }

  const list = sites.data?.sites ?? [];
  const scopes = [...new Set(list.map((s) => s.params?.routing_scope || s.code))].sort();
  const error = sites.error ?? devices.error;
  const actionError = patch.error ?? remove.error ?? assign.error;

  return (
    <div className="ops-page">
      <div className="bar">
        <span className="eyebrow">Sites</span>
      </div>

      {error && (
        <div className="banner err">
          <div className="sub">
            {error instanceof ApiError ? error.message : "Sites not loaded"}
          </div>
        </div>
      )}

      {actionError && (
        <div className="banner err">
          <div className="sub">
            {actionError instanceof ApiError ? actionError.message : "Change failed"}
          </div>
        </div>
      )}

      {released && (
        <div className="banner warn" role="status">
          <div className="sub">
            {describeRelease(released)}{" "}
            <button type="button" className="linkish" onClick={() => setReleased(null)}>
              Dismiss
            </button>
            <div className="dim">Graph placements unchanged until the next collection run</div>
          </div>
        </div>
      )}

      {canEdit && (
        <form className="editorcard" onSubmit={handleCreate} aria-label="Add a site">
          <div className="paramrow">
            <span className="param">
              <label htmlFor="site-code">Code</label>
              <input
                id="site-code"
                spellCheck={false}
                placeholder="DEU-FRA-123123"
                value={draft.code}
                onChange={(e) => setDraft({ ...draft, code: e.target.value })}
              />
            </span>
            <span className="param">
              <label htmlFor="site-name">Name</label>
              <input
                id="site-name"
                placeholder="Frankfurt"
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </span>
            <span className="param">
              <label htmlFor="site-location">Location</label>
              <input
                id="site-location"
                placeholder="Example Street 1"
                value={draft.location}
                onChange={(e) => setDraft({ ...draft, location: e.target.value })}
              />
            </span>
          </div>
          <div className="source-actions card-actions">
            <button className="primary" type="submit" disabled={create.isPending}>
              {create.isPending ? "Adding" : "Add site"}
            </button>
            {create.isError && (
              <span className="sf-danger">
                {create.error instanceof ApiError ? create.error.message : "Site not added"}
              </span>
            )}
          </div>
        </form>
      )}

      {sites.isLoading && <span className="hint">Loading</span>}

      <div className="source-list">
        {list.map((site) => (
          <div className="source-row" key={site.code}>
            <div className="source-row-head">
              <span className="source-name">{site.code}</span>
              {site.name && <span className="source-type">{site.name}</span>}
              {site.location && <span className="hint">{site.location}</span>}
              <span className="badge ok source-updated">
                {site.device_count} device{site.device_count === 1 ? "" : "s"}
              </span>
            </div>
            {renaming === site.code ? (
              <SiteRename
                site={site}
                pending={patch.isPending}
                onSave={(name) => {
                  patch.mutate({ code: site.code, name });
                  setRenaming(null);
                }}
                onCancel={() => setRenaming(null)}
              />
            ) : confirming === site.code ? (
              <SiteDeleteConfirm
                site={site}
                pending={remove.isPending}
                onConfirm={() => {
                  remove.mutate(site.code);
                  setConfirming(null);
                }}
                onCancel={() => setConfirming(null)}
              />
            ) : (
              <div className="source-actions">
                <button
                  type="button"
                  className="linkish"
                  onClick={() => setSelected(selected === site.code ? null : site.code)}
                >
                  {selected === site.code ? "Hide devices" : "Devices"}
                </button>
                {canEdit && (
                  <>
                    <button type="button" className="linkish" onClick={() => setRenaming(site.code)}>
                      Rename
                    </button>
                    <button
                      type="button"
                      className="linkish sf-danger"
                      onClick={() => setConfirming(site.code)}
                    >
                      Delete
                    </button>
                  </>
                )}
              </div>
            )}
            {canEditDefaults && (
              <SiteRoutingScope
                site={site}
                scopes={scopes}
                pending={patch.isPending}
                onSave={(routing_scope) => patch.mutate({ code: site.code, params: { routing_scope } })}
              />
            )}
            {canEdit && (
              <SiteCoordinates
                site={site}
                pending={patch.isPending}
                onSave={(lat, lon) => patch.mutate({ code: site.code, params: { lat, lon } })}
              />
            )}
            {selected === site.code && (
              <div className="site-detail">
                <SiteGroups site={site.code} canEdit={canEditDefaults} />
                <SiteLocations site={site.code} canEdit={canEdit} />
                <SitePlacements
                  site={site.code}
                  devices={devices.data?.devices ?? []}
                  canEdit={canEdit}
                  onClear={(uid) => assign.mutate({ device_uid: uid, site: null })}
                />
                <div className="bar">
                  <span className="eyebrow">Devices at {site.code}</span>
                </div>
                <DeviceTable
                  devices={devices.data?.devices ?? []}
                  sites={list}
                  site={site.code}
                  canEdit={canEdit}
                  onAssign={(uid, code) => assign.mutate({ device_uid: uid, site: code })}
                />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function releaseWarning(site: Site): string {
  const held = [
    site.group_count ? `${site.group_count} group${site.group_count === 1 ? "" : "s"}` : "",
    site.location_count
      ? `${site.location_count} reported location${site.location_count === 1 ? "" : "s"}`
      : "",
    site.placed_count ? `${site.placed_count} device${site.placed_count === 1 ? "" : "s"} placed by hand` : "",
  ].filter(Boolean);
  if (!held.length) return `Delete site ${site.code}`;
  return `Delete site ${site.code}, unplaces ${held.join(", ")}`;
}

function describeRelease(released: SiteRelease): string {
  const count = (n: number, noun: string) => (n ? `${n} ${noun}${n === 1 ? "" : "s"}` : "");
  const moved = [
    count(released.groups.length, "group"),
    count(released.locations.length, "reported location"),
    count(released.devices.length, "device placement"),
  ].filter(Boolean);
  if (!moved.length) return "Site deleted";
  return `Site deleted, unplaced ${moved.join(", ")}`;
}

/** A hand placement outranks the site of a controller's reported location. */
function SitePlacements({
  site,
  devices,
  canEdit,
  onClear,
}: {
  site: string;
  devices: SiteDevice[];
  canEdit: boolean;
  onClear: (uid: string) => void;
}) {
  const here = devices.filter((d) => d.hand_placed && d.site === site);
  return (
    <fieldset className="sf-group">
      <legend>Placed by hand at {site}</legend>
      {here.length === 0 && <div className="hint">No devices placed by hand</div>}
      {here.map((device) => (
        <div className="checkline" key={device.uid}>
          {device.hostname || device.uid} ({device.source || "unknown source"},{" "}
          {device.location_name || device.location_id || "no reported location"})
          {canEdit && (
            <button
              type="button"
              className="linkish"
              aria-label={`Clear the placement of ${device.hostname || device.uid}`}
              onClick={() => onClear(device.uid)}
            >
              Clear
            </button>
          )}
        </div>
      ))}
    </fieldset>
  );
}

/** A group sits at one site. */
function SiteGroups({ site, canEdit }: { site: string; canEdit: boolean }) {
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState("");
  const sources = useQuery({
    queryKey: ["sources"],
    queryFn: () => api<SourcesResponse>("/sources"),
  });
  const move = useMutation<Source, ApiError, { name: string; site: string }>({
    mutationFn: ({ name, site: code }) =>
      api<Source>(`/sources/${encodeURIComponent(name)}`, {
        method: "PATCH",
        body: { config: { site_code: code } },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sources"] });
      queryClient.invalidateQueries({ queryKey: ["sites"] });
      queryClient.invalidateQueries({ queryKey: ["site-devices"] });
      queryClient.invalidateQueries({ queryKey: SITES_GRAPH_KEY });
    },
  });

  const groups = (sources.data?.sources ?? []).filter((s) => s.kind === "group");
  const siteOf = (group: Source) =>
    typeof group.config.site_code === "string" ? group.config.site_code : "";
  const here = groups.filter((g) => siteOf(g) === site);
  const elsewhere = groups.filter((g) => siteOf(g) !== site);

  return (
    <fieldset className="sf-group">
      <legend>Groups at {site}</legend>
      {sources.isLoading && <div className="hint">Loading groups</div>}
      {sources.isError && <div className="hint">{sources.error.message}</div>}
      {move.isError && <div className="hint">{move.error.message}</div>}
      {sources.isSuccess && groups.length === 0 && (
        <div className="hint">No groups</div>
      )}
      {sources.isSuccess && groups.length > 0 && here.length === 0 && (
        <div className="hint">No groups</div>
      )}
      {here.map((group) => (
        <div className="checkline" key={group.name}>
          {group.name} ({group.type})
          {canEdit && (
            <button
              type="button"
              className="linkish"
              aria-label={`Remove ${group.name} from ${site}`}
              disabled={move.isPending}
              onClick={() => move.mutate({ name: group.name, site: "" })}
            >
              Remove
            </button>
          )}
        </div>
      ))}
      {canEdit && elsewhere.length > 0 && (
        <div className="paramrow">
          <span className="param sf-field">
            <label htmlFor={`add-group-${site}`}>Move a group here</label>
            <select
              id={`add-group-${site}`}
              value={adding}
              onChange={(e) => setAdding(e.target.value)}
            >
              <option value="">Choose a group</option>
              {elsewhere.map((group) => (
                <option key={group.name} value={group.name}>
                  {group.name}
                  {siteOf(group) ? ` (at ${siteOf(group)})` : " (no site)"}
                </option>
              ))}
            </select>
          </span>
          <button
            type="button"
            className="linkish"
            disabled={!adding || move.isPending}
            onClick={() => {
              move.mutate({ name: adding, site });
              setAdding("");
            }}
          >
            Move here
          </button>
        </div>
      )}
    </fieldset>
  );
}

/** A binding is by location id. */
function SiteLocations({ site, canEdit }: { site: string; canEdit: boolean }) {
  const queryClient = useQueryClient();
  const locations = useQuery({
    queryKey: ["locations"],
    queryFn: () => api<ReportedLocationsResponse>("/locations"),
  });
  const bind = useMutation<unknown, ApiError, { location: ReportedLocation; site: string | null }>({
    mutationFn: ({ location, site: code }) =>
      api(
        `/locations/${encodeURIComponent(location.source)}/${encodeURIComponent(location.location_id)}`,
        { method: "PATCH", body: { site: code } },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["locations"] });
      queryClient.invalidateQueries({ queryKey: ["sites"] });
      queryClient.invalidateQueries({ queryKey: ["site-devices"] });
      queryClient.invalidateQueries({ queryKey: SITES_GRAPH_KEY });
    },
  });

  const rows = locations.data?.locations ?? [];
  const here = rows.filter((l) => l.site === site);
  const free = rows.filter((l) => !l.site);
  return (
    <fieldset className="sf-group">
      <legend>Reported locations at {site}</legend>
      {locations.isLoading && <div className="hint">Loading locations</div>}
      {locations.isError && <div className="hint">{locations.error.message}</div>}
      {bind.isError && <div className="hint">{bind.error.message}</div>}
      {locations.isSuccess && here.length === 0 && free.length === 0 && (
        <div className="hint">No reported locations</div>
      )}
      {here.map((location) => (
        <div className="checkline" key={`${location.source}/${location.location_id}`}>
          {location.name || location.location_id} ({location.source}, {location.device_count} devices)
          {canEdit && (
            <button
              type="button"
              className="linkish"
              aria-label={`Unbind ${location.name || location.location_id}`}
              disabled={bind.isPending}
              onClick={() => bind.mutate({ location, site: null })}
            >
              Unbind
            </button>
          )}
        </div>
      ))}
      {free.length > 0 && <p className="hint">Unplaced</p>}
      {free.map((location) => (
        <div className="checkline" key={`${location.source}/${location.location_id}`}>
          {location.name || location.location_id} ({location.source}, {location.device_count} devices)
          {canEdit && (
            <button
              type="button"
              className="linkish"
              aria-label={`Bind ${location.name || location.location_id} to ${site}`}
              disabled={bind.isPending}
              onClick={() => bind.mutate({ location, site })}
            >
              Bind to {site}
            </button>
          )}
        </div>
      ))}
    </fieldset>
  );
}

/** The scope in which same-named VRFs at this site count as one routing
 * domain (core/l3domain.py). */
function SiteRoutingScope({
  site,
  scopes,
  pending,
  onSave,
}: {
  site: Site;
  scopes: string[];
  pending: boolean;
  onSave: (scope: string | null) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(site.params?.routing_scope ?? "");
  const own = site.params?.routing_scope ?? "";
  const shared = scopes.filter((s) => s !== site.code);

  if (!editing) {
    return (
      <div className="checkline">
        <span className="hint">
          Routing scope <b>{own || site.code}</b>
          {own ? "" : " (site code)"}
        </span>
        <button type="button" className="linkish" onClick={() => setEditing(true)}>
          Change
        </button>
      </div>
    );
  }
  return (
    <div className="paramrow" role="group" aria-label={`Routing scope for ${site.code}`}>
      <span className="param">
        <label htmlFor={`routing-${site.code}`}>Routing scope</label>
        <input
          id={`routing-${site.code}`}
          value={value}
          list={shared.length ? `scopes-${site.code}` : undefined}
          placeholder={site.code}
          onChange={(e) => setValue(e.target.value)}
        />
        {shared.length > 0 && (
          <datalist id={`scopes-${site.code}`}>
            {shared.map((scope) => (
              <option key={scope} value={scope} />
            ))}
          </datalist>
        )}
      </span>
      <button
        type="button"
        className="linkish"
        disabled={pending}
        onClick={() => {
          onSave(value.trim() || null);
          setEditing(false);
        }}
      >
        Save
      </button>
      <button type="button" className="linkish" onClick={() => setEditing(false)}>
        Cancel
      </button>
    </div>
  );
}

/**
 * A site whose code is an Equinix IBX code (`FR2`, `AM3`) is offered its
 * metro's point. */
function SiteCoordinates({
  site,
  pending,
  onSave,
}: {
  site: Site;
  pending: boolean;
  onSave: (lat: number | null, lon: number | null) => void;
}) {
  const [editing, setEditing] = useState(false);
  const placed = site.params?.lat != null && site.params?.lon != null;
  const [lat, setLat] = useState(placed ? String(site.params?.lat) : "");
  const [lon, setLon] = useState(placed ? String(site.params?.lon) : "");
  const metro = metroOf(site.code);
  const parsed = { lat: Number(lat), lon: Number(lon) };
  const empty = lat.trim() === "" && lon.trim() === "";
  const valid =
    empty ||
    (lat.trim() !== "" &&
      lon.trim() !== "" &&
      Number.isFinite(parsed.lat) &&
      Number.isFinite(parsed.lon) &&
      Math.abs(parsed.lat) <= 90 &&
      Math.abs(parsed.lon) <= 180);

  if (!editing) {
    return (
      <div className="checkline">
        <span className="hint">
          {placed ? (
            <>
              On the map at{" "}
              <b>
                {site.params?.lat}, {site.params?.lon}
              </b>
            </>
          ) : (
            "Not on the map"
          )}
        </span>
        <button type="button" className="linkish" onClick={() => setEditing(true)}>
          {placed ? "Move" : "Place on map"}
        </button>
      </div>
    );
  }
  return (
    <div className="paramrow" role="group" aria-label={`Place ${site.code}`}>
      <span className="param">
        <label htmlFor={`lat-${site.code}`}>Latitude</label>
        <input
          id={`lat-${site.code}`}
          inputMode="decimal"
          value={lat}
          placeholder="50.11"
          onChange={(e) => setLat(e.target.value)}
        />
      </span>
      <span className="param">
        <label htmlFor={`lon-${site.code}`}>Longitude</label>
        <input
          id={`lon-${site.code}`}
          inputMode="decimal"
          value={lon}
          placeholder="8.68"
          onChange={(e) => setLon(e.target.value)}
        />
      </span>
      {metro && (
        <button
          type="button"
          className="linkish"
          onClick={() => {
            setLat(String(metro.lat));
            setLon(String(metro.lon));
          }}
        >
          Use {metro.name}
        </button>
      )}
      <button
        type="button"
        className="linkish"
        disabled={pending || !valid}
        onClick={() => {
          if (empty) onSave(null, null);
          else onSave(parsed.lat, parsed.lon);
          setEditing(false);
        }}
      >
        Save
      </button>
      <button type="button" className="linkish" onClick={() => setEditing(false)}>
        Cancel
      </button>
    </div>
  );
}

function SiteRename({
  site,
  pending,
  onSave,
  onCancel,
}: {
  site: Site;
  pending: boolean;
  onSave: (name: string) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(site.name);
  return (
    <div className="paramrow" role="group" aria-label={`Rename ${site.code}`}>
      <span className="param">
        <label htmlFor={`rename-${site.code}`}>Name</label>
        <input
          id={`rename-${site.code}`}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </span>
      <button type="button" className="linkish" disabled={pending} onClick={() => onSave(name)}>
        Save
      </button>
      <button type="button" className="linkish" onClick={onCancel}>
        Cancel
      </button>
    </div>
  );
}

function SiteDeleteConfirm({
  site,
  pending,
  onConfirm,
  onCancel,
}: {
  site: Site;
  pending: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="banner warn" role="group" aria-label={`Delete ${site.code}`}>
      <div className="sub">
        {releaseWarning(site)}{" "}
        <button type="button" className="linkish sf-danger" disabled={pending} onClick={onConfirm}>
          Delete {site.code}
        </button>
        <button type="button" className="linkish" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function DeviceTable({
  devices,
  sites,
  site,
  canEdit,
  onAssign,
}: {
  devices: SiteDevice[];
  sites: Site[];
  site: string;
  canEdit: boolean;
  onAssign: (uid: string, site: string | null) => void;
}) {
  const [showOtherSites, setShowOtherSites] = useState(false);
  const rows = devices.filter((d) => showOtherSites || d.site === site || !d.site);
  if (devices.length === 0) return <span className="hint">No devices</span>;

  return (
    <>
    <label><input type="checkbox" checked={showOtherSites} onChange={(e) => setShowOtherSites(e.target.checked)} /> Show devices at other sites</label>
    <table>
      <thead>
        <tr>
          <th>Device</th>
          <th>Platform</th>
          <th>Site</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((d) => (
          <tr key={d.uid}>
            <td>{d.hostname ?? d.uid}</td>
            <td className="dim">{d.platform ?? "not known"}</td>
            <td>
              {canEdit && d.can_place ? (
                <select
                  aria-label={`Site for ${d.hostname ?? d.uid}`}
                  value={d.hand_placed ? (d.site ?? "") : ""}
                  onChange={(e) => onAssign(d.uid, e.target.value || null)}
                >
                  <option value="">{d.site && !d.hand_placed ? d.site : "no site"}</option>
                  {sites.map((s) => (
                    <option key={s.code} value={s.code}>
                      {s.code}
                    </option>
                  ))}
                </select>
              ) : (
                (d.site ?? "no site")
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    </>
  );
}
