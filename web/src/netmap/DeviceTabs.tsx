/**
 * The tabs of a device in the site diagram's panel. Overview is what the
 * drawing knows. Interfaces lists the device's interfaces at the run
 * (GET /api/hst/device), each with its far end in the drawing; a click opens
 * its facts (GET /api/hst/interface) and its configuration
 * (GET /api/hst/interface-text). Routing, ACLs, NAT and Version are the
 * sections of the device's raw payload (GET /api/hst/device-text), read when
 * one of them opens. The configuration needs the interfaces.read permission.
 */

import { useState, type ReactNode } from "react";
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { useCurrentUser } from "../auth";
import type { DeviceText, InterfaceFacts, InterfaceText, Tier3 } from "../hst/data/api";

const TABS = [
  ["overview", "Overview"],
  ["interfaces", "Interfaces"],
  ["routing", "Routing"],
  ["acls", "ACLs"],
  ["nat", "NAT"],
  ["version", "Version"],
] as const;
type Tab = (typeof TABS)[number][0];

const NO_PERMISSION = "No interfaces.read permission";

function problem(err: unknown, missing: string): string {
  if (err instanceof ApiError && err.status === 404) return missing;
  return err instanceof Error ? err.message : String(err);
}

/** The last part of a uid: the VRF or LAG name of `vrf:dev:leaf-a:hosting`. */
const tail = (uid: string) => uid.slice(uid.lastIndexOf(":") + 1);

/** The address of an IpAddress uid, `ip:{anchor}:{addr}`. */
function addressOf(uid: string): string {
  const m = /(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d+)?|[0-9a-f]*:[0-9a-f:]+(?:\/\d+)?)$/i.exec(uid);
  return m ? m[1] : uid;
}

function fact(label: string, value: unknown) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <>
      <dt>{label}</dt>
      <dd>{String(value)}</dd>
    </>
  );
}

/** The query string of an HST read pinned to the run the drawing shows. */
function pinned(uid: string, snapshot: number | null | undefined): string {
  const q = `uid=${encodeURIComponent(uid)}`;
  return snapshot == null ? q : `${q}&snapshot=${encodeURIComponent(String(snapshot))}`;
}

export default function DeviceTabs({
  uid,
  snapshot,
  overview,
  links,
}: {
  uid: string;
  snapshot: number | null | undefined;
  overview: ReactNode;
  /** interface name to its far end in the drawing */
  links: ReadonlyMap<string, string>;
}) {
  const [tab, setTab] = useState<Tab>("overview");
  const canRead = !!useCurrentUser()?.permissions.includes("interfaces.read");
  const q = pinned(uid, snapshot);
  const device = useQuery({
    queryKey: ["hst-device", uid, snapshot],
    queryFn: () => api<Tier3>(`/hst/device?${q}`),
    enabled: tab === "interfaces",
  });
  const text = useQuery({
    queryKey: ["hst-device-text", uid, snapshot],
    queryFn: () => api<DeviceText>(`/hst/device-text?${q}`),
    enabled: canRead && tab !== "overview" && tab !== "interfaces",
    retry: false,
  });
  const title = TABS.find(([key]) => key === tab)![1];
  return (
    <>
      <div className="nm-tabs" role="tablist" aria-label="Device details">
        {TABS.map(([key, label]) => (
          <button key={key} type="button" role="tab" aria-selected={tab === key} onClick={() => setTab(key)}>
            {label}
          </button>
        ))}
      </div>
      {tab === "overview" ? (
        overview
      ) : tab === "interfaces" ? (
        <Interfaces query={device} snapshot={snapshot} links={links} canRead={canRead} />
      ) : (
        <ConfigSection query={text} section={tab} title={title} canRead={canRead} />
      )}
    </>
  );
}

function Interfaces({
  query,
  snapshot,
  links,
  canRead,
}: {
  query: UseQueryResult<Tier3>;
  snapshot: number | null | undefined;
  links: ReadonlyMap<string, string>;
  canRead: boolean;
}) {
  const [open, setOpen] = useState<string | null>(null);
  if (query.isPending) return <p className="hint nm-tab-body">Loading interfaces</p>;
  if (query.isError) return <p className="banner err nm-tab-body">{problem(query.error, "Device not in the run")}</p>;
  if (query.data.state === "cold") return <p className="hint nm-tab-body">Cold run</p>;
  const rows = (query.data.categories.n_interfaces ?? [])
    .map((r) => ({ uid: String(r.uid), name: String(r.name ?? r.uid) }))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
  if (rows.length === 0) return <p className="hint nm-tab-body">No interfaces</p>;
  return (
    <ul className="nm-ifaces">
      {rows.map((r) => {
        const far = links.get(r.name);
        return (
          <li key={r.uid}>
            <button
              type="button"
              className="linkish"
              aria-expanded={open === r.uid}
              onClick={() => setOpen(open === r.uid ? null : r.uid)}
            >
              {r.name}
            </button>
            {far && <span className="nm-iface-far"> to {far}</span>}
            {open === r.uid && <InterfaceDetail uid={r.uid} snapshot={snapshot} canRead={canRead} />}
          </li>
        );
      })}
    </ul>
  );
}

function InterfaceDetail({
  uid,
  snapshot,
  canRead,
}: {
  uid: string;
  snapshot: number | null | undefined;
  canRead: boolean;
}) {
  const q = pinned(uid, snapshot);
  const facts = useQuery({
    queryKey: ["hst-interface", uid, snapshot],
    queryFn: () => api<InterfaceFacts>(`/hst/interface?${q}`),
  });
  const text = useQuery({
    queryKey: ["hst-interface-text", uid, snapshot],
    queryFn: () => api<InterfaceText>(`/hst/interface-text?${q}`),
    enabled: canRead,
    retry: false,
  });
  const f = facts.data;
  const i = f?.interface ?? {};
  return (
    <div className="nm-iface">
      {facts.isError && <p className="banner err">{problem(facts.error, "Interface not in the run")}</p>}
      {f && (
        <dl>
          {fact("Description", i.description)}
          {fact("Kind", i.kind)}
          {fact("Admin state", typeof i.admin_up === "boolean" ? (i.admin_up ? "up" : "down") : undefined)}
          {fact("Oper state", i.oper_status ?? f.port?.oper_status)}
          {fact("MTU", i.mtu)}
          {fact("VRF", f.contexts.map(tail).join(", "))}
          {fact("Addresses", f.addresses.map(addressOf).join(", "))}
          {fact("LAG", f.lags.map(tail).join(", "))}
        </dl>
      )}
      {!canRead ? (
        <p className="hint">{NO_PERMISSION}</p>
      ) : text.isPending ? (
        <p className="hint">Loading configuration</p>
      ) : text.isError ? (
        <p className="hint">{problem(text.error, "No configuration collected")}</p>
      ) : (
        <pre className="nm-config" aria-label={`Configuration of ${f?.name ?? uid}`}>
          {text.data.text}
        </pre>
      )}
    </div>
  );
}

function ConfigSection({
  query,
  section,
  title,
  canRead,
}: {
  query: UseQueryResult<DeviceText>;
  section: string;
  title: string;
  canRead: boolean;
}) {
  if (!canRead) return <p className="hint nm-tab-body">{NO_PERMISSION}</p>;
  if (query.isPending) return <p className="hint nm-tab-body">Loading configuration</p>;
  if (query.isError)
    return <p className="hint nm-tab-body">{problem(query.error, "No configuration collected")}</p>;
  const found = query.data.sections.find((s) => s.key === section);
  if (!found) return <p className="hint nm-tab-body">No {title} section</p>;
  return (
    <div className="nm-tab-body">
      {found.parts.map((p) => (
        <section key={p.command} className="nm-config-part">
          <h5>{p.command}</h5>
          <pre className="nm-config" aria-label={p.command}>
            {p.text}
          </pre>
        </section>
      ))}
      {query.data.fetched_ts !== null && (
        <p className="hint">Fetched {new Date(query.data.fetched_ts).toLocaleString()}</p>
      )}
    </div>
  );
}
