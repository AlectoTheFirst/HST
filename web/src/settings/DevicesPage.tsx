import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { atLeast, useAuth } from "../auth";
import { SITES_GRAPH_KEY } from "../inventory/queryKeys";
import type {
  Site,
  SiteDevicesResponse,
  SitesResponse,
  SourcesResponse,
  SourceTypesResponse,
} from "../api/types";
import { DevicesPanel } from "./DevicesPanel";

/** A location id is unique per source only. */
function placeKey(device: { source?: string | null; location_id?: string | null }): string {
  return `${device.source ?? ""} ${device.location_id ?? ""}`;
}

export default function DevicesPage() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canManage = !!user && atLeast(user.role, "operator");

  const devices = useQuery({
    queryKey: ["site-devices", "all"],
    queryFn: () => api<SiteDevicesResponse>("/sites/devices"),
  });
  const sites = useQuery({
    queryKey: ["sites"],
    queryFn: () => api<SitesResponse>("/sites"),
  });
  const assign = useMutation({
    mutationFn: (body: { device_uid: string; site: string | null }) =>
      api<unknown>("/sites/assign", { method: "POST", body }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["site-devices"] });
      queryClient.invalidateQueries({ queryKey: ["sites"] });
      queryClient.invalidateQueries({ queryKey: SITES_GRAPH_KEY });
    },
  });

  const [sourceFilter, setSourceFilter] = useState("");
  const [placeFilter, setPlaceFilter] = useState("");
  const [picked, setPicked] = useState<ReadonlySet<string>>(() => new Set());
  const [bulkSite, setBulkSite] = useState("");
  const [bulkFailed, setBulkFailed] = useState<readonly string[]>([]);

  const all = [...(devices.data?.devices ?? [])].sort((a, b) =>
    String(a.hostname ?? a.uid).localeCompare(String(b.hostname ?? b.uid)),
  );
  const rows = all.filter(
    (d) =>
      (!sourceFilter || (d.source ?? "") === sourceFilter) &&
      (!placeFilter || placeKey(d) === placeFilter),
  );
  const sourceNames = [...new Set(all.map((d) => d.source ?? "").filter(Boolean))].sort();
  const places = [
    ...new Map(
      all
        .filter((d) => d.location_id)
        .map((d) => [
          placeKey(d),
          { name: d.location_name || (d.location_id as string), source: d.source ?? "" },
        ]),
    ).entries(),
  ].sort(([, a], [, b]) => a.name.localeCompare(b.name));
  const shared = new Set(
    places.map(([, p]) => p.name).filter((name, i, names) => names.indexOf(name) !== i),
  );
  const byUid = new Map(all.map((d) => [d.uid, d]));
  const error = devices.error ?? sites.error;
  const assignError = assign.error;

  function label(device: { hostname: string | null; uid: string }) {
    return device.hostname ?? device.uid;
  }

  function toggle(uid: string) {
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(uid)) next.delete(uid);
      else next.add(uid);
      return next;
    });
  }

  async function assignPicked() {
    const failed: string[] = [];
    setBulkFailed([]);
    for (const uid of picked) {
      try {
        await assign.mutateAsync({ device_uid: uid, site: bulkSite || null });
      } catch {
        failed.push(uid);
      }
    }
    setBulkFailed(failed);
    setPicked(new Set(failed));
  }

  return (
    <div className="ops-page">
      <div className="bar">
        <span className="eyebrow">Devices</span>
      </div>

      <DeviceConfiguration />

      {error && (
        <div className="banner err">
          <div className="sub">
            {error instanceof ApiError ? error.message : "Devices not loaded"}
          </div>
        </div>
      )}
      {assignError && (
        <div className="banner err">
          <div className="sub">
            {assignError instanceof ApiError ? assignError.message : "Device not placed"}
          </div>
        </div>
      )}
      {bulkFailed.length > 0 && (
        <div className="banner err">
          <div className="sub">
            Not placed:{" "}
            {bulkFailed.map((uid) => label(byUid.get(uid) ?? { hostname: null, uid })).join(", ")}
          </div>
        </div>
      )}

      {all.length > 0 && (
        <div className="paramrow" role="group" aria-label="Filter and assign devices">
          <span className="param sf-field">
            <label htmlFor="device-source-filter">Source</label>
            <select
              id="device-source-filter"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
            >
              <option value="">All sources</option>
              {sourceNames.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </span>
          <span className="param sf-field">
            <label htmlFor="device-place-filter">Reported location</label>
            <select
              id="device-place-filter"
              value={placeFilter}
              onChange={(e) => setPlaceFilter(e.target.value)}
            >
              <option value="">All locations</option>
              {places.map(([key, place]) => (
                <option key={key} value={key}>
                  {shared.has(place.name) ? `${place.name} (${place.source})` : place.name}
                </option>
              ))}
            </select>
          </span>
          {canManage && (
            <span className="param sf-field">
              <label htmlFor="device-bulk-site">Place selected at</label>
              <select id="device-bulk-site" value={bulkSite} onChange={(e) => setBulkSite(e.target.value)}>
                <option value="">Clear placement</option>
                {(sites.data?.sites ?? []).map((site: Site) => (
                  <option key={site.code} value={site.code}>
                    {site.code}
                  </option>
                ))}
              </select>
            </span>
          )}
          {canManage && (
            <button
              type="button"
              className="primary"
              disabled={picked.size === 0 || assign.isPending}
              onClick={assignPicked}
            >
              Place {picked.size} selected
            </button>
          )}
        </div>
      )}

      {devices.isLoading ? (
        <span className="hint">Loading</span>
      ) : rows.length === 0 ? (
        <span className="tableempty">No devices</span>
      ) : (
        <table className="device-table">
          <thead>
            <tr>
              {canManage && <th></th>}
              <th>Device</th>
              <th>Platform</th>
              <th>Source</th>
              <th>Reported location</th>
              <th>Site</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((device) => (
              <tr key={device.uid}>
                {canManage && (
                  <td>
                    {device.can_place && (
                      <input
                        type="checkbox"
                        aria-label={`Select ${label(device)}`}
                        checked={picked.has(device.uid)}
                        onChange={() => toggle(device.uid)}
                      />
                    )}
                  </td>
                )}
                <td>{label(device)}</td>
                <td>{device.platform ?? ""}</td>
                <td>{device.source || ""}</td>
                <td>{device.location_name || device.location_id || ""}</td>
                <td>
                  {canManage && device.can_place ? (
                    <select
                      aria-label={`Site for ${device.hostname ?? device.uid}`}
                      disabled={assign.isPending || sites.isLoading || sites.isError}
                      value={device.hand_placed ? (device.site ?? "") : ""}
                      onChange={(event) => {
                        assign.mutate({
                          device_uid: device.uid,
                          site: event.target.value || null,
                        });
                      }}
                    >
                      {/* the empty value clears the hand placement */}
                      <option value="">{device.site && !device.hand_placed ? device.site : "no site"}</option>
                      {(sites.data?.sites ?? []).map((site: Site) => (
                        <option key={site.code} value={site.code}>
                          {site.code}
                        </option>
                      ))}
                    </select>
                  ) : (
                    (device.site ?? "no site")
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function DeviceConfiguration() {
  const { user } = useAuth();
  const [selected, setSelected] = useState("");
  const [visited, setVisited] = useState<Set<string>>(() => new Set());
  const canEdit = !!user?.permissions.includes("sources.write");
  const canRead = !!user?.permissions.includes("runs.manage");
  const sources = useQuery({ queryKey: ["sources"], queryFn: () => api<SourcesResponse>("/sources"), enabled: canRead });
  const types = useQuery({ queryKey: ["source-types"], queryFn: () => api<SourceTypesResponse>("/source-types"), enabled: canRead });
  const fleets = (sources.data?.sources ?? []).filter((source) => source.kind === "group");
  const current = fleets.find((source) => source.name === selected) ?? fleets[0];
  const error = sources.error ?? types.error;
  if (!canRead) return null;
  return <section className="editorcard" aria-label="Device configuration">
    <div className="bar"><span className="eyebrow">Device configuration</span></div>
    {error && <p className="banner err" role="alert">{error.message}</p>}
    {(sources.isLoading || types.isLoading) && <p>Loading device configuration</p>}
    {current && <>
      <span className="param sf-field">
        <label htmlFor="device-connection">Group</label>
        <select id="device-connection" value={current.name} onChange={(e) => {
          setVisited((previous) => new Set([...previous, current.name, e.target.value]));
          setSelected(e.target.value);
        }}>
          {fleets.map((source) => <option key={source.name} value={source.name}>{source.name} ({source.type})</option>)}
        </select>
      </span>
      {fleets.map((source) => <div key={source.name} hidden={source.name !== current.name}>
        {(source.name === current.name || visited.has(source.name)) && <DevicesPanel sourceName={source.name} canManage={canEdit} />}
      </div>)}
    </>}
    {sources.isSuccess && types.isSuccess && !fleets.length && <p>
      No groups <Link to="/settings/groups">Add group</Link>
    </p>}
  </section>;
}
