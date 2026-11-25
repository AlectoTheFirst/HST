/**
 * The network map: the estate on the world map,
 * and a site drawn as a network diagram from the planner's view model
 * (GET /api/topology, hst/diagram/planner.py).
 *
 * With no site open, the estate level shows the backbone of hubs, data
 * centers and colocation sites on a muted world map, with a branch count
 * badge on each (EstateMap.tsx), from GET /api/sites/graph. A site opens in
 * the same pane, and the Estate button returns to the estate where it was
 * left, with the same badges open. Inside a site,
 * a zoom too far out to read a cable shows the blocks with one line per pair
 * of blocks (level 2); a zoom in shows the devices and every cable (level 3)
 * and the port names (level 4).
 *
 * The page is the instance lifecycle and the chrome. The ELK graph, the
 * conversion to Cytoscape and the segment math are pure and tested in
 * layout.ts, the stylesheet in style.ts. ELK runs in a worker (elk.ts). The
 * network segment bars and the client badges are drawn after the layout from
 * the device positions (segments.ts), and a saved view keeps the layer, the
 * picks, the Segments and Clients options and the expanded badges.
 */

import type cytoscape from "cytoscape";
import type { ElkNode } from "elkjs/lib/elk-api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type {
  EquinixMetroView,
  MapClientGroup,
  MapDevice,
  NetworkMapLayout,
  NetworkMapView,
  SegmentClientsPage,
  SiteEdgeKind,
  SiteGraphEdge,
  SiteGraphPayload,
  SitesResponse,
  SiteTraceResponse,
  TopologyModel,
  TopologyNode,
  TopologySegment,
} from "../api/types";
import { siteSelection, useAiContext, useAiPaneId } from "../ai/context";
import { useCurrentUser } from "../auth";
import { SITES_GRAPH_KEY } from "../inventory/queryKeys";
import { readPalette, watchTheme } from "../explore/graphStyle";
import { withLayouts } from "../graph/cytoscape";
import type { View } from "../diagram/useCanvas";
import { describePair, KIND_LABEL, KIND_ORDER } from "../diagram/siteEdges";
import { layout } from "./elk";
import { layoutSaver, type LayoutSaver } from "./layoutSaver";
import EstateMap, { type Group } from "./EstateMap";
import { branchRows, homes } from "./backbone";
import { DEFAULT_KINDS, siteClass } from "./estate";
import {
  blockBundles,
  crossesBlocks,
  DEVICE_HEIGHT,
  drawingPositions,
  PLAIN_DRAWING,
  stubs,
  toElements,
  toElkGraph,
  toFlatElkGraph,
  unrouted,
  withDrawingPositions,
  withPositions,
  type CyElement,
} from "./layout";
import { fabricModel, isFabric, metroOf, type FabricDrawing } from "./fabric";
import { freshnessLabel, tableAges } from "../diagram/freshness";
import { domainKey, vlanOptions, vrfOptions } from "../diagram/overlay";
import { count, paint, type Layer } from "./overlays";
import { clientElements, clientsText, groupIn, groupKey, macText, segmentLabel, shownDomains, whereText } from "./segments";
import {
  behindRow,
  canvasMeasure,
  deviceBoxes,
  dropPath,
  dropRoutes,
  endpointOffset,
  layoutRow,
  linkPrefixes,
  planRow,
  routeMovedDrops,
  rowBars,
  rowElements,
  segmentId,
  withBoxes,
  type Box,
  type Measure,
  type Row,
} from "./segrow";
import { layoutBoxes, placeTags } from "./tags";
import { FLOW_CLASSES, FLOW_LINK, flowPaint } from "./flows";
import FlowPanel, { flowSelectionOf, useApplicationFlows } from "./FlowPanel";
import { outcomeOf, selectedConnections, type FlowSelection } from "../applications/flows";
import { FADED, stylesheet } from "./style";
import Legend, { DEFAULT_LOOK, Options, type Look } from "./Legend";
import Overview from "./Overview";
import DeviceTabs from "./DeviceTabs";
import { categoryOf, decorate, speedKey, symbolOf, type Category, type SpeedKey } from "./look";
import { exploreApi } from "../api/explore";
import UnifiedSearch from "../search/UnifiedSearch";
import type { Kind, SearchHit } from "../search/types";
import "./networkmap.css";

/** The kinds the map's search asks for: what the map draws, and the ARP and
 *  MAC table rows, which open on their device or segment. */
const SEARCH_KINDS: readonly Kind[] = ["device", "site", "segment", "arp", "mac"];

/** A device or a segment the search asks the open drawing to select. */
export interface MapFocus {
  kind: "device" | "segment";
  /** the device uid, or the segment's bridge domain */
  id: string;
  /** what the hit was called, for a notice */
  name: string;
}

/** The site code of a Site node's uid (hst/core/uid.py `site_uid`). */
function siteSlug(code: string): string {
  return code.trim().toLowerCase().replace(/ /g, "-").replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
}

const ZOOM_STEP = 1.4;
const MIN_ZOOM = 0.05;
const MAX_ZOOM = 4;
const FIT_PAD = 32;
/** below this zoom the blocks and their bundles show */
const LEVEL2_ZOOM = 0.35;
/** the wait after the last drag before the positions are saved: a drag of several devices is one save */
const SAVE_DELAY = 300;
const capital = (text: string) => text.charAt(0).toUpperCase() + text.slice(1);
const CLASS_TEXT = { hub: "SD-WAN hub", dc: "Data center", colo: "Colocation", branch: "Branch" } as const;

const BASIS_TEXT: Record<string, string> = {
  collector: "the collector",
  evidence: "FHRP evidence",
  hostname: "the hostname",
  default: "the collector default",
  tier: "the tier",
  inferred: "the cabled neighbors",
  none: "no tier and no tiered neighbor",
};

type Selection =
  | { kind: "device"; id: string }
  | { kind: "cable"; id: string }
  /** a segment bar: its bridge domain, and in L3 its prefix */
  | { kind: "segment"; id: string; bd: string | null; site: string | null; cidr: string | null }
  /** a client badge, by its group key (segments.ts `groupKey`) */
  | { kind: "clients"; id: string; group: string }
  | null;

/** The page of the segment client list in the side panel. */
const SEGMENT_PAGE = 100;

const layoutPath = (site: string) => `/network-map/layouts/site/${encodeURIComponent(site)}`;

/** The open drawing: one site code, or several joined by commas, drawn as one
 *  picture with the cables between them (the planner takes a list of sites). */
const codesOf = (site: string) => site.split(",").filter(Boolean);
const topologyPath = (site: string) => "/topology?" + codesOf(site).map((c) => `site=${encodeURIComponent(c)}`).join("&");
/** A union of sites keeps no layout of its own: each site's is its own. */
const NO_LAYOUT: NetworkMapLayout = { scope: "", positions: {}, revision: 0, updated_by: null, updated_at: null };

/** What a saved view keeps of an open site diagram: the layer, the picked VLAN
 *  and routing domain, the Segments and Clients options, and the expanded
 *  client badges (segments.ts `groupKey`). */
export interface DiagramState {
  layer?: Layer;
  vid?: number | null;
  domain?: string | null;
  segments?: boolean;
  clients?: boolean;
  groups?: string[];
}

/** What a saved view holds: the open site, the line kinds, the estate camera,
 *  the open badges (major site codes, null for the "No hub" group), the
 *  application flows shown on a site diagram, and the state of the open
 *  diagram. */
interface ViewState extends DiagramState {
  site?: string;
  kinds?: SiteEdgeKind[];
  estate?: View;
  expanded?: Group[];
  flows?: FlowSelection | null;
}

const LAYERS: readonly Layer[] = ["phys", "l2", "l3"];

/** The diagram state of a saved view: each field that has its right type, and nothing else. */
export function diagramOf(state: Record<string, unknown>): DiagramState {
  const out: DiagramState = {};
  if (typeof state.layer === "string" && (LAYERS as readonly string[]).includes(state.layer)) out.layer = state.layer as Layer;
  if (typeof state.vid === "number" && Number.isInteger(state.vid)) out.vid = state.vid;
  if (typeof state.domain === "string") out.domain = state.domain;
  if (typeof state.segments === "boolean") out.segments = state.segments;
  if (typeof state.clients === "boolean") out.clients = state.clients;
  if (Array.isArray(state.groups)) out.groups = state.groups.filter((g): g is string => typeof g === "string");
  return out;
}

interface OlderViewState {
  backbone?: { expanded?: unknown };
}

const isView = (v: unknown): v is View =>
  typeof v === "object" && v !== null && ["x", "y", "w", "h"].every((k) => typeof (v as Record<string, unknown>)[k] === "number");

/** The open badges of a saved view, from either shape. */
export function expandedOf(state: ViewState & OlderViewState): Group[] {
  const list = Array.isArray(state.expanded) ? state.expanded : state.backbone?.expanded;
  return Array.isArray(list) ? list.filter((g): g is Group => g === null || typeof g === "string") : [];
}

/** The drawing a workspace scope opens (workspace/layout.ts `open-map`): a
 *  site code, `sites/A,B` for two sites as one picture, or `fabric/<metro>`
 *  for the Equinix Fabric of a metro (netmap/fabric.ts). A routing scope
 *  (`scope/<name>`) opens the estate. */
export function siteOfScope(scope: string | undefined): string {
  if (!scope || scope.startsWith("scope/")) return "";
  if (scope.startsWith("sites/")) return codesOf(scope.slice("sites/".length)).sort().join(",");
  return scope;
}

export default function NetworkMapPage({ initialSite }: { initialSite?: string } = {}) {
  /** the site whose diagram is open; "" is the estate */
  const [site, setSite] = useState(() => siteOfScope(initialSite));
  /** the site selected on the estate level */
  const [picked, setPicked] = useState<string | null>(null);
  const [kinds, setKinds] = useState<ReadonlySet<SiteEdgeKind>>(DEFAULT_KINDS);
  // the estate view follows every pan in a ref, and is kept in state when a
  // site opens
  const estateView = useRef<View | undefined>(undefined);
  const [leftView, setLeftView] = useState<View | undefined>(undefined);
  const keepView = useCallback((view: View) => {
    estateView.current = view;
  }, []);
  /** the open badges of the estate */
  const [expanded, setExpanded] = useState<Group[]>([]);
  /** the branch list in the side panel: a major site's, or null for "No hub" */
  const [listed, setListed] = useState<Group | undefined>(undefined);
  /** the diagram state a saved view opens with, and the open diagram's own */
  const [diagramInit, setDiagramInit] = useState<DiagramState | undefined>(undefined);
  const diagramState = useRef<DiagramState>({});
  const keepDiagram = useCallback((state: DiagramState) => {
    diagramState.current = state;
  }, []);
  const open = (code: string) => {
    if (site === "") setLeftView(estateView.current);
    setDiagramInit(undefined);
    setSite(code);
  };
  // a saved view, or a reset, draws the estate or the site afresh
  const [drawing, setDrawing] = useState(0);
  /** the application and connections the Flows panel shows */
  const [flows, setFlows] = useState<FlowSelection | null>(null);
  const user = useCurrentUser();
  const canWrite = !!user?.permissions.includes("sites.write");
  const queryClient = useQueryClient();
  const keepLayout = useCallback(
    (scope: string, layout: NetworkMapLayout) => queryClient.setQueryData(["network-map-layout", scope], layout),
    [queryClient],
  );

  const sites = useQuery<SitesResponse>({
    queryKey: ["sites"],
    queryFn: () => api<SitesResponse>("/sites"),
    staleTime: 60_000,
  });
  const siteList = useMemo(() => [...(sites.data?.sites ?? [])].sort((a, b) => a.code.localeCompare(b.code)), [sites.data]);
  const focus = isFabric(site) ? null : site || picked;
  useAiContext(
    useAiPaneId(),
    focus ? { selection: [siteSelection(focus, siteList.find((s) => s.code === focus)?.name)] } : null,
  );

  const estate = useQuery<SiteGraphPayload>({
    queryKey: SITES_GRAPH_KEY,
    queryFn: () => api<SiteGraphPayload>("/sites/graph"),
    enabled: site === "",
    staleTime: 60_000,
  });
  const model = useQuery<Partial<FabricDrawing> & { model: TopologyModel }>({
    queryKey: ["topology", site],
    queryFn: () =>
      isFabric(site)
        ? api<EquinixMetroView>(`/equinix/metro?metro=${encodeURIComponent(metroOf(site))}`).then(fabricModel)
        : api<TopologyModel>(topologyPath(site)).then((m) => ({ model: m })),
    enabled: site !== "",
  });
  /** a union of sites, or a Fabric drawing, keeps no layout of its own */
  const keepsLayout = site !== "" && !site.includes(",") && !isFabric(site);
  const stored = useQuery<NetworkMapLayout>({
    queryKey: ["network-map-layout", site],
    queryFn: () => api<NetworkMapLayout>(layoutPath(site)),
    enabled: keepsLayout,
  });
  const views = useQuery<{ views: NetworkMapView[] }>({
    queryKey: ["network-map-views"],
    queryFn: () => api<{ views: NetworkMapView[] }>("/network-map/views"),
    staleTime: 30_000,
  });
  const [viewId, setViewId] = useState("");
  const [naming, setNaming] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const applyView = (id: string) => {
    setViewId(id);
    const view = views.data?.views.find((v) => v.id === id);
    if (!view) return;
    const state = view.state as ViewState & OlderViewState;
    if (Array.isArray(state.kinds)) setKinds(new Set(state.kinds));
    const camera = isView(state.estate) ? state.estate : undefined;
    estateView.current = camera;
    setLeftView(camera);
    setExpanded(expandedOf(state));
    setListed(undefined);
    setPicked(null);
    setDiagramInit(diagramOf(view.state));
    setSite(typeof state.site === "string" ? state.site : "");
    setFlows(flowSelectionOf(state.flows));
    setDrawing((n) => n + 1);
  };
  const saveView = async (name: string) => {
    const state: ViewState = {
      site,
      kinds: [...kinds],
      estate: site === "" ? estateView.current : leftView,
      expanded,
      ...(site === "" ? {} : diagramState.current),
      flows,
    };
    try {
      const made = await api<NetworkMapView>("/network-map/views", { method: "POST", body: { name, state } });
      await queryClient.invalidateQueries({ queryKey: ["network-map-views"] });
      setViewId(made.id);
      setNaming(null);
      setNotice(null);
    } catch (err) {
      setNotice(err instanceof ApiError && err.status === 409 ? `A view named ${name} exists` : failure(err));
    }
  };
  const deleteView = async () => {
    const view = views.data?.views.find((v) => v.id === viewId);
    if (!view) return;
    try {
      await api(`/network-map/views/${encodeURIComponent(view.id)}?expected_revision=${view.revision}`, { method: "DELETE" });
      setViewId("");
      setNotice(null);
    } catch (err) {
      setNotice(failure(err));
    }
    await queryClient.invalidateQueries({ queryKey: ["network-map-views"] });
  };

  const toggle = (kind: SiteEdgeKind) =>
    setKinds((prev) => {
      const next = new Set(prev);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });
  const failure = (err: unknown) => (err instanceof ApiError ? err.message : String(err));

  /** the device or segment the search opened, for the drawing to select once drawn */
  const [mapFocus, setMapFocus] = useState<MapFocus | null>(null);
  const drawn = site !== "" ? model.data?.model : undefined;
  const siteCodeOf = (uid: string) =>
    siteList.find((s) => `site:${siteSlug(s.code)}` === uid)?.code ?? uid.replace(/^site:/, "");
  /** Selects a device in the open drawing, or opens the site it is located in first. */
  const focusDevice = async (uid: string, name: string) => {
    if (drawn?.nodes.some((n) => n.kind === "device" && n.id === uid)) {
      setMapFocus({ kind: "device", id: uid, name });
      return;
    }
    try {
      const located = await exploreApi.neighbors({ uid, type: "LOCATED_IN", direction: "out", label: "Site", limit: 1 });
      const siteUid = located.items[0]?.uid;
      if (!siteUid) {
        setNotice(`${name} is in no site`);
        return;
      }
      const code = siteCodeOf(siteUid);
      setMapFocus({ kind: "device", id: uid, name });
      if (code !== site) open(code);
    } catch (err) {
      setNotice(failure(err));
    }
  };
  const openHit = (hit: SearchHit) => {
    setNotice(null);
    const target = hit.target ?? (hit.uid ? { kind: hit.kind, uid: hit.uid } : null);
    const rowDevice = typeof hit.fields.device_uid === "string" && hit.fields.device_uid ? hit.fields.device_uid : null;
    const rowName = String(hit.fields.device ?? "") || rowDevice || hit.name;
    if (target?.kind === "site") {
      open(siteCodeOf(target.uid));
    } else if (target?.kind === "device") {
      void focusDevice(target.uid, hit.kind === "device" ? hit.name || target.uid : rowName);
    } else if (target?.kind === "segment" && drawn?.segments?.some((s) => s.bd === target.uid)) {
      setMapFocus({ kind: "segment", id: target.uid, name: hit.name || target.uid });
    } else if (rowDevice) {
      void focusDevice(rowDevice, rowName);
    } else {
      setNotice(site === "" ? "No site open" : `${hit.name || target?.uid || hit.key} is not in this drawing`);
    }
  };

  return (
    <div className="nm-page">
      <div className="paramrow nm-toolbar">
        <UnifiedSearch label="Search the map" className="nm-search" defaultKinds={SEARCH_KINDS} onOpen={openHit} clearOnOpen popover />
        {site !== "" && (
          <button type="button" onClick={() => open("")}>
            Estate
          </button>
        )}
        <label>
          Site{" "}
          <select value={site} onChange={(e) => open(e.target.value)} aria-label="Site">
            <option value="">All sites</option>
            {site.includes(",") && <option value={site}>{codesOf(site).join(" and ")}</option>}
            {isFabric(site) && <option value={site}>Equinix Fabric {metroOf(site)}</option>}
            {siteList.map((s) => (
              <option key={s.code} value={s.code}>
                {s.name && s.name !== s.code ? `${s.code}, ${s.name}` : s.code}
              </option>
            ))}
          </select>
        </label>
        <label>
          View{" "}
          <select value={viewId} onChange={(e) => applyView(e.target.value)} aria-label="Saved view">
            <option value="">No saved view</option>
            {(views.data?.views ?? []).map((v) => (
              <option key={v.id} value={v.id}>
                {v.name}
              </option>
            ))}
          </select>
        </label>
        {canWrite && naming === null && (
          <button type="button" onClick={() => setNaming("")}>
            Save view
          </button>
        )}
        {canWrite && naming !== null && (
          <form
            className="nm-naming"
            onSubmit={(e) => {
              e.preventDefault();
              if (naming.trim()) void saveView(naming.trim());
            }}
          >
            <input value={naming} onChange={(e) => setNaming(e.target.value)} aria-label="View name" />
            <button type="submit">Save</button>
            <button type="button" onClick={() => setNaming(null)}>
              Cancel
            </button>
          </form>
        )}
        {canWrite && viewId !== "" && (
          <button type="button" onClick={() => void deleteView()}>
            Delete view
          </button>
        )}
        {site === "" && (
          <fieldset className="nm-kinds">
            <legend className="sr-only">Counted links</legend>
            {KIND_ORDER.map((k) => (
              <label key={k}>
                <input type="checkbox" checked={kinds.has(k)} onChange={() => toggle(k)} /> {capital(KIND_LABEL[k])}
              </label>
            ))}
          </fieldset>
        )}
      </div>
      {sites.error && <p className="banner err" role="alert">{failure(sites.error)}</p>}
      {notice && <p className="banner err nm-notice" role="alert">{notice}</p>}
      {site === "" && kinds.has("l3") && (estate.data?.shared_subnets?.length ?? 0) > 0 && (
        <p className="hint nm-shared">
          Shared prefixes not drawn:{" "}
          {estate.data!.shared_subnets!.map((s) => `${s.cidr} on ${s.sites} sites`).join(", ")}
        </p>
      )}
      {site === "" ? (
        estate.isPending ? (
          <p className="hint" role="status">Loading the sites</p>
        ) : estate.error ? (
          <p className="banner err" role="alert">{failure(estate.error)}</p>
        ) : (
          <div className="nm-body">
            <EstateMap
              key={drawing}
              payload={estate.data}
              kinds={kinds}
              selected={picked}
              onSelect={setPicked}
              onOpen={open}
              expanded={expanded}
              onExpanded={setExpanded}
              onList={(group) => {
                setListed(group);
                if (group !== undefined) setPicked(null);
              }}
              initialView={leftView}
              onView={keepView}
            />
            {picked ? (
              <SitePanel
                payload={estate.data}
                kinds={kinds}
                code={picked}
                onOpen={open}
                onClose={() => setPicked(null)}
              />
            ) : (
              listed !== undefined && (
                <BranchList
                  payload={estate.data}
                  kinds={kinds}
                  group={listed}
                  onOpen={open}
                  onClose={() => setListed(undefined)}
                />
              )
            )}
          </div>
        )
      ) : model.isPending || (stored.isPending && keepsLayout) ? (
        <p className="hint" role="status">Loading the topology</p>
      ) : model.error || stored.error ? (
        <p className="banner err" role="alert">{failure(model.error ?? stored.error)}</p>
      ) : model.data.model.nodes.length === 0 ? (
        <p className="hint">No devices in the pinned run</p>
      ) : (
        // a new site, a saved view or a reset is a new drawing, with its own layout state
        <Diagram
          key={`${site}:${drawing}`}
          model={model.data.model}
          circuits={model.data.circuits}
          site={site}
          stored={stored.data ?? NO_LAYOUT}
          canWrite={canWrite && keepsLayout}
          initial={diagramInit}
          onState={keepDiagram}
          flows={flows}
          onFlows={setFlows}
          onNotice={setNotice}
          onSaved={keepLayout}
          focusOn={mapFocus}
          onFocused={(found) => {
            if (!found && mapFocus) setNotice(`${mapFocus.name} is not in this drawing`);
            setMapFocus(null);
          }}
          onReset={async () => {
            await queryClient.invalidateQueries({ queryKey: ["network-map-layout", site] });
            // a reset moves the devices back, and keeps the layer and the options
            setDiagramInit(diagramState.current);
            setDrawing((n) => n + 1);
          }}
        />
      )}
    </div>
  );
}

/** The selected site on the estate level: what it is, and its lines by kind. */
function SitePanel({
  payload,
  kinds,
  code,
  onOpen,
  onClose,
}: {
  payload: SiteGraphPayload;
  kinds: ReadonlySet<SiteEdgeKind>;
  code: string;
  onOpen: (code: string) => void;
  onClose: () => void;
}) {
  const s = payload.sites.find((x) => x.code === code);
  if (!s) return null;
  const counts = new Map<SiteEdgeKind, number>();
  for (const e of payload.edges) {
    if (e.a === code || e.b === code) counts.set(e.kind, (counts.get(e.kind) ?? 0) + e.count);
  }
  const tiers = Object.entries(s.tiers ?? {});
  // a branch counts under one major site; the others it links to are named
  const others = homes(payload, kinds).get(code)?.others ?? [];
  return (
    <aside className="nm-panel" aria-label="Site details">
      <header>
        {s.name && s.name !== s.code ? `${s.code}, ${s.name}` : s.code}
        <button type="button" onClick={onClose} aria-label="Close details">Close</button>
      </header>
      <dl>
        <dt>Kind</dt>
        <dd>{CLASS_TEXT[siteClass(s)]}</dd>
        <dt>Devices</dt>
        <dd>{s.devices}</dd>
        {tiers.length > 0 && (
          <>
            <dt>Tiers</dt>
            <dd>{tiers.map(([t, n]) => `${n} ${t}`).join(", ")}</dd>
          </>
        )}
        {KIND_ORDER.filter((k) => counts.get(k)).map((k) => (
          <div key={k} className="nm-panel-row">
            <dt>{capital(KIND_LABEL[k])}</dt>
            <dd>{counts.get(k)}</dd>
          </div>
        ))}
      </dl>
      {others.length > 0 && <p className="nm-panel-note">Also on {others.join(", ")}</p>}
      <p className="nm-panel-actions">
        <button type="button" onClick={() => onOpen(code)}>Open the diagram</button>
      </p>
      <Connections payload={payload} code={code} onOpen={onOpen} />
    </aside>
  );
}

/** The branches of one badge on the estate, or of the "No hub" group
 *  (`group` null): each row opens the site. */
function BranchList({
  payload,
  kinds,
  group,
  onOpen,
  onClose,
}: {
  payload: SiteGraphPayload;
  kinds: ReadonlySet<SiteEdgeKind>;
  group: string | null;
  onOpen: (code: string) => void;
  onClose: () => void;
}) {
  const rows = branchRows(payload, kinds, group);
  return (
    <aside className="nm-panel" aria-label="Branches">
      <header>
        {group === null ? "No hub" : `Branches of ${group}`}
        <button type="button" onClick={onClose} aria-label="Close the list">Close</button>
      </header>
      <ul className="nm-branches">
        {rows.map((r) => (
          <li key={r.code}>
            <button type="button" className="linkish" onClick={() => onOpen(r.code)}>
              {r.name && r.name !== r.code ? `${r.code}, ${r.name}` : r.code}
            </button>
            <span className="nm-branch-note">
              {r.total === 1 ? "1 link" : `${r.total} links`}
              {r.others.length > 0 ? `, also on ${r.others.join(", ")}` : ""}
            </span>
          </li>
        ))}
      </ul>
    </aside>
  );
}

export function Diagram({
  model,
  circuits,
  site,
  stored,
  canWrite,
  initial,
  onState,
  flows,
  onFlows,
  onNotice,
  onReset,
  onSaved,
  focusOn,
  onFocused,
}: {
  model: TopologyModel;
  /** a Fabric drawing: the circuits of each line between a Fabric port and a far end */
  circuits?: ReadonlyMap<string, string[]>;
  site: string;
  /** the positions people moved in this site, and the revision they were read at */
  stored: NetworkMapLayout;
  canWrite: boolean;
  /** the layer, the picks, the options and the expanded badges a saved view opens with */
  initial?: DiagramState;
  /** told of each change of those, for the next saved view */
  onState?: (state: DiagramState) => void;
  flows: FlowSelection | null;
  onFlows: (selection: FlowSelection | null) => void;
  onNotice: (text: string | null) => void;
  onReset: () => void;
  /** told of each layout the server stored */
  onSaved?: (site: string, layout: NetworkMapLayout) => void;
  /** a device or segment to select and center once the drawing is laid out */
  focusOn?: MapFocus | null;
  /** told whether the drawing holds what `focusOn` asked for */
  onFocused?: (found: boolean) => void;
}) {
  const positions = useRef<Record<string, { x: number; y: number }>>({ ...stored.positions });
  const revision = useRef(stored.revision);
  /** the stored positions with the moves since, for the reset button */
  const [shownPositions, setShownPositions] = useState(stored.positions);

  const settle = useRef({ onNotice, onSaved });
  useEffect(() => {
    settle.current = { onNotice, onSaved };
  });
  const saver = useRef<LayoutSaver | null>(null);
  useEffect(() => {
    const made = layoutSaver<NetworkMapLayout>({
      send: () =>
        api<NetworkMapLayout>(layoutPath(site), {
          method: "PUT",
          body: { positions: positions.current, expected_revision: revision.current },
        }),
      onSaved: (saved) => {
        revision.current = saved.revision;
        settle.current.onSaved?.(site, saved);
      },
      onSettled: (err) =>
        settle.current.onNotice(
          err === null
            ? null
            : err instanceof ApiError && err.status === 409
              ? "Layout of this site saved by another user"
              : err instanceof Error
                ? err.message
                : String(err),
        ),
      delay: SAVE_DELAY,
    });
    saver.current = made;
    // a move that waits for its send goes out when the drawing closes
    return () => made.close();
  }, [site]);

  // a reset moves back the devices of the open drawing; the other drawings keep theirs
  const reset = async () => {
    saver.current?.cancel();
    try {
      const others = withDrawingPositions(positions.current, drawingKey, {});
      if (Object.keys(others).length)
        await api<NetworkMapLayout>(layoutPath(site), {
          method: "PUT",
          body: { positions: others, expected_revision: revision.current },
        });
      else await api(`${layoutPath(site)}?expected_revision=${revision.current}`, { method: "DELETE" });
      onNotice(null);
      onReset();
    } catch (err) {
      onNotice(err instanceof Error ? err.message : String(err));
    }
  };

  const host = useRef<HTMLDivElement | null>(null);
  const cy = useRef<cytoscape.Core | null>(null);
  /** the open canvas, for the overview */
  const [core, setCore] = useState<cytoscape.Core | null>(null);
  const [look, setLook] = useState<Look>(() => ({
    ...DEFAULT_LOOK,
    segments: initial?.segments ?? DEFAULT_LOOK.segments,
    clients: initial?.clients ?? DEFAULT_LOOK.clients,
  }));
  const lookRef = useRef(look);
  const [optionsOpen, setOptionsOpen] = useState(false);
  /** the level 2 check of the open canvas: the look reruns it when the frames show or hide */
  const relevel = useRef<() => void>(() => {});
  // The draw, a look change, a layer change and a drag each ask for the port tags; the asks of one frame
  // place them once.
  const retagFrame = useRef(0);
  const retagLater = useCallback((target: cytoscape.Core, tagBoxes: ReadonlyMap<string, Box>, tagMeasure: Measure) => {
    window.cancelAnimationFrame(retagFrame.current);
    retagFrame.current = window.requestAnimationFrame(() => {
      retagFrame.current = 0;
      if (!target.destroyed()) retag(target, lookRef.current, tagBoxes, tagMeasure);
    });
  }, []);
  const [selected, setSelected] = useState<Selection>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [laying, setLaying] = useState(true);
  const nodes = useMemo(() => new Map(model.nodes.map((n) => [n.id, n])), [model]);
  const crossed = useMemo(() => crossesBlocks(model), [model]);
  const [ready, setReady] = useState(0);
  const [layer, setLayer] = useState<Layer>(initial?.layer ?? "phys");
  const vlanList = useMemo(() => vlanOptions(model.vlans ?? []), [model]);
  const vrfList = useMemo(() => vrfOptions(model.subnets ?? []), [model]);
  const [vid, setVid] = useState<number | null>(initial?.vid ?? null);
  const [domain, setDomain] = useState<string | null>(initial?.domain ?? null);
  /** the expanded client badges, by group key */
  const [groups, setGroups] = useState<ReadonlySet<string>>(() => new Set(initial?.groups ?? []));
  /** counts the drags, so the bars and the badges follow a moved device */
  const [moves, setMoves] = useState(0);
  const pickedVid = vlanList.some((o) => o.vid === vid) ? vid : (vlanList[0]?.vid ?? null);
  const pickedDomain = vrfList.some((o) => o.key === domain) ? domain : (vrfList[0]?.key ?? null);
  const layerPaint = useMemo(() => paint(model, layer, pickedVid, pickedDomain), [model, layer, pickedVid, pickedDomain]);
  useEffect(() => {
    onState?.({ layer, vid: pickedVid, domain: pickedDomain, segments: look.segments, clients: look.clients, groups: [...groups] });
  }, [onState, layer, pickedVid, pickedDomain, look.segments, look.clients, groups]);
  // the application flows over the drawing (flows.ts); a saved selection opens the panel
  const [flowsOpen, setFlowsOpen] = useState(() => !!flows?.connections.length);
  const flowData = useApplicationFlows(flowsOpen ? flows : null, model.snapshot);
  const flowsPaint = useMemo(
    () => flowPaint(model, flowsOpen ? selectedConnections(flowData.data, flows) : []),
    [model, flowsOpen, flowData.data, flows],
  );

  const select = useCallback((next: Selection) => {
    setSelected(next);
    const core = cy.current;
    if (!core) return;
    core.batch(() => {
      core.elements().unselect().removeClass(FADED);
      if (next === null) return;
      const el = core.$id(next.id);
      el.select();
      if (next.kind === "device") {
        const keep = el.closedNeighborhood().union(el.ancestors());
        core.elements().difference(keep.union(keep.ancestors())).addClass(FADED);
      }
    });
  }, []);

  const layoutKind = look.layout;
  const measure = useMemo(() => canvasMeasure(), []);
  const boxes = useMemo(() => deviceBoxes(model, measure), [model, measure]);
  const elkBoxes = useMemo(() => layoutBoxes(model, boxes, measure), [model, boxes, measure]);
  // the segment row of the L2 and L3 layers is part of the tiered layout (segrow.ts)
  const rowOn = look.segments && layer !== "phys" && layoutKind === "tiered";
  const planned = useMemo<Row | null>(() => {
    if (!rowOn) return null;
    const bars = rowBars(model, layer, pickedVid, pickedDomain);
    return bars.length ? planRow(model, bars, measure, elkBoxes) : null;
  }, [rowOn, model, layer, pickedVid, pickedDomain, measure, elkBoxes]);
  /** the drawing the moved positions belong to: each segment row places its bars anew */
  const drawingKey = !planned ? PLAIN_DRAWING : layer === "l2" ? `l2/${pickedVid}` : `l3/${pickedDomain}`;
  /** the row the open canvas draws, with the slot order of the layout */
  const drawnRow = useRef<Row | null>(null);
  useEffect(() => {
    let cancelled = false;
    const laying: Promise<{ laid: ElkNode; row: Row | null }> = planned
      ? layoutRow(layout, toFlatElkGraph(model), model, planned)
      : layout(layoutKind === "blocks" ? toElkGraph(model) : withBoxes(toFlatElkGraph(model), elkBoxes)).then((laid) => ({ laid, row: null }));
    laying
      .then(({ laid, row }) => {
        if (cancelled || !host.current) return;
        cy.current?.destroy();
        drawnRow.current = row;
        const drawn = toElements(model, laid);
        const base = row ? [...drawn, ...rowElements(row, laid)] : drawn;
        let elements = routeMovedDrops(withPositions([...base, ...blockBundles(model)], drawingPositions(positions.current, drawingKey)));
        // a cable across the row takes a free place in it, where the devices and the bars now are
        if (row) elements = behindRow(elements, row);
        // the force layout moves every device off its ELK route: the cables go straight
        if (layoutKind === "organic") elements = elements.map((e) => (isRouted(e) ? { ...e, classes: unrouted(e.classes) } : e));
        const core = withLayouts()({
          container: host.current,
          elements: decorate(elements, model),
          style: stylesheet(readPalette()),
          layout: { name: "preset", fit: true, padding: FIT_PAD },
          minZoom: MIN_ZOOM,
          maxZoom: MAX_ZOOM,
          // everyone moves devices, and a frame moves its devices; a person
          // with sites.write saves the positions. Shift and drag selects several.
          boxSelectionEnabled: true,
        });
        if (layoutKind === "organic") relax(core, drawingPositions(positions.current, drawingKey));
        fitView(core);
        core.nodes(".exit, .segtag, .segtap, .segjoint").ungrabify();
        core.nodes(".segtag, .segtap, .segjoint").unselectify();
        core.on("tap", "node.device", (e) => select({ kind: "device", id: e.target.id() }));
        const moved = (devices: cytoscape.NodeCollection) => {
          const next = drawingPositions(positions.current, drawingKey);
          devices.forEach((node) => {
            const { x, y } = node.position();
            next[node.id()] = { x: Math.round(x), y: Math.round(y) };
            node.connectedEdges(".cable").forEach((edge) => {
              edge.classes(unrouted(edge.classes().join(" ")));
            });
          });
          reroute(core, devices);
          if (drawnRow.current) rethread(core, drawnRow.current);
          positions.current = withDrawingPositions(positions.current, drawingKey, next);
          setShownPositions(positions.current);
          // the layer effect below depends on `moves` and places the tags
          setMoves((n) => n + 1);
          if (canWrite) saver.current?.schedule();
        };
        core.on("dragfree", "node.device, node.segbar", (e) => moved(e.target as cytoscape.NodeCollection));
        // a bar carries its tags and the ends of its drops
        let held: { x: number; y: number } | null = null;
        core.on("grab", "node.segbar", (e) => {
          held = { ...(e.target as cytoscape.NodeSingular).position() };
        });
        core.on("drag", "node.segbar", (e) => {
          const bar = e.target as cytoscape.NodeSingular;
          if (!held) return;
          const now = bar.position();
          const delta = { x: now.x - held.x, y: now.y - held.y };
          held = { ...now };
          core.nodes(".segtag, .segtap").filter((n) => n.data("bar") === bar.id()).shift(delta);
        });
        core.on("dragfree", "node.site, node.block, node.group", (e) => {
          moved((e.target as cytoscape.NodeSingular).descendants(".device"));
        });
        core.on("tap", "edge.cable", (e) => select({ kind: "cable", id: e.target.id() }));
        // a segment bar opens its segment; a client badge opens and closes its glyphs
        core.on("tap", "node.segbar", (e) =>
          select({
            kind: "segment",
            id: e.target.id(),
            bd: e.target.data("bd") ?? null,
            site: e.target.data("site") ?? null,
            cidr: e.target.data("cidr") ?? null,
          }),
        );
        core.on("tap", "node.clientbadge", (e) => {
          const key = String(e.target.data("group"));
          setGroups((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
          });
          select({ kind: "clients", id: e.target.id(), group: key });
        });
        // a stub box stands for the line to it
        core.on("tap", "node.exit", (e) => select({ kind: "cable", id: `${e.target.id()}:cable` }));
        // level 2: past the threshold the bundles stand in for the cables between blocks
        const crossing = core.edges().filter((e) => crossed.has(e.id()));
        let overview: boolean | null = null;
        const level = () => {
          const far = core.zoom() < LEVEL2_ZOOM && lookRef.current.frames;
          if (far === overview) return;
          overview = far;
          core.batch(() => {
            core.edges(".bundle").toggleClass("on", far);
            crossing.toggleClass("off", far);
            core.nodes(".block, .site").toggleClass("overview", far);
          });
        };
        core.on("zoom", level);
        relevel.current = () => {
          overview = null;
          level();
        };
        level();
        core.on("tap", (e) => {
          if (e.target === core) select(null);
        });
        cy.current = core;
        setCore(core);
        setLaying(false);
        setReady((n) => n + 1);
      })
      .catch((err: unknown) => {
        if (!cancelled) setFailure(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, [model, select, crossed, canWrite, layoutKind, planned, drawingKey, boxes, elkBoxes, measure]);

  useEffect(
    () => () => {
      window.cancelAnimationFrame(retagFrame.current);
      cy.current?.destroy();
    },
    [],
  );

  // the search's pick: selected and centered once the drawing is laid out
  useEffect(() => {
    if (!focusOn || ready === 0) return;
    let found = false;
    if (focusOn.kind === "device" && nodes.get(focusOn.id)?.kind === "device") {
      found = true;
      // the selection is drawn on the canvas as well as kept in state, as a tap does
      // eslint-disable-next-line react-hooks/set-state-in-effect
      select({ kind: "device", id: focusOn.id });
      const el = cy.current?.$id(focusOn.id);
      if (el && el.nonempty()) cy.current?.center(el);
    } else if (focusOn.kind === "segment") {
      const seg = (model.segments ?? []).find((s) => s.bd === focusOn.id);
      if (seg) {
        found = true;
        select({ kind: "segment", id: segmentId(seg), bd: seg.bd, site: seg.site ?? null, cidr: null });
      }
    }
    onFocused?.(found);
  }, [focusOn, ready, nodes, model, select, onFocused]);

  // the legend's choice over the drawn elements
  useEffect(() => {
    lookRef.current = look;
    const core = cy.current;
    if (!core) return;
    core.batch(() => {
      const cables = core.edges(".cable");
      cables.removeClass("hid");
      for (const key of look.hiddenSpeeds) cables.filter(`.spd-${key}`).addClass("hid");
      const devices = core.nodes(".device");
      devices.removeClass("hid");
      for (const key of look.hiddenCategories) devices.filter(`.cat-${key}`).addClass("hid");
      // a stub goes with its device
      core.nodes(".exit").forEach((stub) => {
        const owners = stub.neighborhood("node.device");
        const ownerHidden = owners.nonempty() && owners.filter(".hid").length === owners.length;
        stub.toggleClass("hid", ownerHidden || (!look.undiscovered && stub.hasClass("undiscovered")));
      });
      devices.toggleClass("noaddr", !look.addresses);
      cables.toggleClass("noports", !look.ports);
      cables.toggleClass("along", look.alongLine);
      cables.toggleClass("speedtext", look.speedAsText);
      cables.filter(".routed").toggleClass("bent", look.routes);
      const frames = core.nodes(".site, .block, .group");
      frames.toggleClass("bare", !look.frames);
      if (look.frames) frames.grabify();
      else frames.ungrabify();
    });
    relevel.current();
    retagLater(core, boxes, measure);
  }, [look, ready, boxes, measure, retagLater]);

  const speedCounts = useMemo(() => {
    const out = new Map<SpeedKey, number>();
    for (const c of model.cables) out.set(speedKey(c.speed_mbps), (out.get(speedKey(c.speed_mbps)) ?? 0) + 1);
    return out;
  }, [model]);
  const categoryCounts = useMemo(() => {
    const out = new Map<Category, number>();
    for (const n of model.nodes) {
      if (n.kind !== "device") continue;
      const key = categoryOf(symbolOf(n.role, n.tier));
      out.set(key, (out.get(key) ?? 0) + 1);
    }
    return out;
  }, [model]);

  const clientsOn = look.clients;
  // the prefix of each routed link of the picked domain, on its cable in L3
  const links = useMemo(() => (layer === "l3" ? linkPrefixes(model, pickedDomain) : new Map<string, string>()), [layer, model, pickedDomain]);
  const held = useMemo(() => new Set((model.segments ?? []).flatMap((s) => s.cidrs)), [model]);
  // the layer's paint over the drawn elements, and the client badges under the
  // devices' captions; a new layer, a pick, an option or a drag draws them
  // from clean. The segment bars are part of the layout.
  useEffect(() => {
    const core = cy.current;
    if (!core) return;
    core.batch(() => {
      core.elements().removeClass("ov-on ov-off ov-both ov-half link");
      core.remove(core.edges(".adjacency").union(core.nodes(".clientbadge, .clientglyph")));
      for (const [id, cls] of layerPaint.classes) core.$id(id).addClass(cls);
      for (const [id, cidr] of links) core.$id(id).data("linkPrefix", cidr).addClass("link");
      const at = new Map(
        core.nodes(".device").map((n) => {
          const box = boxes.get(n.id());
          const bottom = box ? box.height - DEVICE_HEIGHT / 2 : undefined;
          return [n.id(), { ...n.position(), width: Number(n.data("width")) || 120, bottom }] as const;
        }),
      );
      const badges = clientsOn ? clientElements(model, layer, pickedVid, pickedDomain, at, groups) : [];
      // a drawn bar stands in for the dashed lines of its prefixes
      const extra = drawnRow.current ? layerPaint.extra.filter((e) => !held.has(String(e.data.label))) : layerPaint.extra;
      if (extra.length) core.add(extra);
      if (badges.length) {
        const added = core.add(badges);
        added.nodes().ungrabify();
        added.nodes(".clientglyph").unselectify();
      }
    });
    retagLater(core, boxes, measure);
  }, [layerPaint, ready, layer, clientsOn, links, held, boxes, measure, pickedVid, pickedDomain, groups, moves, model, retagLater]);

  useEffect(() => {
    const core = cy.current;
    if (!core) return;
    core.batch(() => {
      core.elements().removeClass(FLOW_CLASSES);
      core.remove(core.edges(`.${FLOW_LINK}`));
      for (const [id, cls] of flowsPaint.classes) core.$id(id).addClass(cls);
      if (flowsPaint.extra.length) core.add(flowsPaint.extra);
    });
  }, [flowsPaint, ready]);

  const [palette, setPalette] = useState(readPalette);
  useEffect(
    () =>
      watchTheme(() => {
        const next = readPalette();
        setPalette(next);
        cy.current?.style(stylesheet(next));
      }),
    [],
  );

  const zoomBy = (factor: number) => {
    const core = cy.current;
    if (!core) return;
    core.zoom({
      level: Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, core.zoom() * factor)),
      renderedPosition: { x: core.width() / 2, y: core.height() / 2 },
    });
  };

  const devices = model.nodes.filter((n) => n.kind === "device");
  const device = selected?.kind === "device" ? nodes.get(selected.id) : undefined;
  const cable = selected?.kind === "cable" ? model.cables.find((c) => c.id === selected.id) : undefined;
  // a line to a stub: a cable that leaves the drawing, or a LAG member with no cable
  const stub = selected?.kind === "cable" && !cable ? stubs(model).find((s) => `${s.id}:cable` === selected.id) : undefined;
  const nameOf = (id: string) => nodes.get(id)?.label ?? id;
  const segment = selected?.kind === "segment" ? selected : undefined;
  const clientGroup = selected?.kind === "clients" ? (model.clients ?? []).find((g) => groupKey(g) === selected.group) : undefined;
  // the bars the drawing shows, for its text alternative
  const shownBars = useMemo(() => planned?.bars.map((b) => b.bar) ?? [], [planned]);
  const shownBds = useMemo(() => shownDomains(model, layer, pickedVid, pickedDomain), [model, layer, pickedVid, pickedDomain]);
  const shownGroups = look.clients
    ? (model.clients ?? []).filter((g) => nodes.has(g.dev) && groupIn(g, shownBds).count > 0)
    : [];
  const toggleGroup = (key: string) =>
    setGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const drawnDevices = new Set(devices.map((n) => n.id));

  return (
    <div className="nm-body">
      <div className="nm-stage">
        <div className="nm-canvas" ref={host} aria-hidden="true" />
        <div className="nm-layers">
          <div className="segs" role="radiogroup" aria-label="Layer">
            {(["phys", "l2", "l3"] as const).map((value) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={layer === value}
                className={layer === value ? "on" : ""}
                onClick={() => setLayer(value)}
              >
                {value === "phys" ? "Physical" : value === "l2" ? "L2" : "L3"}
              </button>
            ))}
          </div>
          {layer === "l2" && vlanList.length > 0 && (
            <select aria-label="VLAN" value={pickedVid ?? ""} onChange={(e) => setVid(Number(e.target.value))}>
              {vlanList.map((o) => (
                <option key={o.vid} value={o.vid}>
                  {o.label}
                </option>
              ))}
            </select>
          )}
          {layer === "l3" && vrfList.length > 0 && (
            <select aria-label="Routing domain" value={pickedDomain ?? ""} onChange={(e) => setDomain(e.target.value)}>
              {vrfList.map((o) => (
                <option key={o.key} value={o.key}>
                  {o.label}
                </option>
              ))}
            </select>
          )}
          {layerPaint.note && <span className="nm-layernote">{layerPaint.note}</span>}
          <div className="segs">
            <button
              type="button"
              aria-pressed={flowsOpen}
              className={flowsOpen ? "on" : ""}
              disabled={model.snapshot === null}
              onClick={() => setFlowsOpen((v) => !v)}
            >
              Flows
            </button>
          </div>
          <div className="segs">
            <button
              type="button"
              aria-pressed={optionsOpen}
              className={optionsOpen ? "on" : ""}
              onClick={() => setOptionsOpen((v) => !v)}
            >
              Options
            </button>
          </div>
        </div>
        {optionsOpen && <Options look={look} onLook={setLook} onClose={() => setOptionsOpen(false)} />}
        <Legend
          look={look}
          onLook={setLook}
          speedCounts={speedCounts}
          categoryCounts={categoryCounts}
          dark={palette.dark}
          unknownColor={palette.line}
        />
        <Overview core={core} version={ready} />
        {flowsOpen && (
          <FlowPanel
            snapshot={model.snapshot}
            selection={flows}
            onSelection={onFlows}
            flows={flowData}
            nameOf={nameOf}
            drawn={drawnDevices}
            note={flowsPaint.note}
            onClose={() => setFlowsOpen(false)}
          />
        )}
        {laying && !failure && <p className="hint nm-overlay" role="status">Laying out {count(devices.length, "device", "devices")}</p>}
        {failure && <p className="banner err nm-overlay" role="alert">Layout failed: {failure}</p>}
        <div className="nm-zoom" role="group" aria-label="Zoom">
          <button type="button" onClick={() => zoomBy(ZOOM_STEP)} aria-label="Zoom in">+</button>
          <button type="button" onClick={() => zoomBy(1 / ZOOM_STEP)} aria-label="Zoom out">-</button>
          <button type="button" onClick={() => cy.current && fitView(cy.current)}>Fit</button>
          {canWrite && Object.keys(drawingPositions(shownPositions, drawingKey)).length > 0 && (
            <button type="button" onClick={() => void reset()}>
              Reset layout
            </button>
          )}
        </div>
      </div>
      {segment && (
        <SegmentPanel
          key={segment.id}
          model={model}
          site={site}
          bd={segment.bd}
          segSite={segment.site}
          cidr={segment.cidr}
          domain={pickedDomain}
          nameOf={nameOf}
          onClose={() => select(null)}
        />
      )}
      {clientGroup && (
        <ClientsPanel
          group={clientGroup}
          bds={shownBds}
          snapshot={model.snapshot}
          segments={model.segments ?? []}
          nameOf={nameOf}
          onSegment={(s) => select({ kind: "segment", id: segmentId(s), bd: s.bd, site: s.site ?? null, cidr: null })}
          onClose={() => select(null)}
        />
      )}
      {(device || cable || stub) && (
        <aside className={device ? "nm-panel nm-panel-wide" : "nm-panel"} aria-label={device ? "Device details" : "Cable details"}>
          <header>
            {device ? device.label : "Cable"}
            <button type="button" onClick={() => select(null)} aria-label="Close details">Close</button>
          </header>
          {device &&
            // a Fabric port or far end of a Fabric drawing is no collected device
            (circuits && device.role === "cloud" ? (
              <DeviceDetails device={device} clients={[]} />
            ) : (
              <DeviceTabs
                key={device.id}
                uid={device.id}
                snapshot={model.snapshot}
                links={linksOf(model, device.id, nameOf)}
                overview={<DeviceDetails device={device} clients={(model.clients ?? []).filter((g) => g.dev === device.id)} />}
              />
            ))}
          {cable && (
            <dl>
              <dt>A end</dt>
              <dd>{nameOf(cable.from.dev)} {cable.from.port ?? ""}</dd>
              <dt>B end</dt>
              <dd>{nameOf(cable.to.dev)} {cable.to.port ?? ""}</dd>
              <dt>Source</dt>
              <dd>{cable.source ?? "not stated"}</dd>
              {circuits?.has(cable.id) && (
                <>
                  <dt>Circuits</dt>
                  <dd>
                    <ul className="nm-clients">
                      {circuits.get(cable.id)!.map((text) => (
                        <li key={text}>{text}</li>
                      ))}
                    </ul>
                  </dd>
                </>
              )}
              {cable.lateral && (
                <>
                  <dt>Placement</dt>
                  <dd>Both ends at one depth</dd>
                </>
              )}
              {model.lags
                .filter((l) => l.cables.includes(cable.id))
                .map((l) => (
                  <div key={l.id} className="nm-panel-row">
                    <dt>LAG</dt>
                    <dd>
                      {l.name ?? "LAG"} on {nameOf(l.dev)}
                      {l.multi_chassis
                        ? `, multi-chassis to ${l.far.map(nameOf).join(" and ")}, joined from the cables and the redundancy group`
                        : ""}
                    </dd>
                  </div>
                ))}
            </dl>
          )}
          {stub && (
            <dl>
              <dt>A end</dt>
              <dd>{nameOf(stub.dev)} {stub.port ?? ""}</dd>
              <dt>B end</dt>
              <dd>{stub.farName !== null ? `${stub.farName} ${stub.farPort ?? ""}, outside this drawing` : stub.label}</dd>
              <dt>Source</dt>
              <dd>{stub.source ?? "not stated"}</dd>
            </dl>
          )}
        </aside>
      )}
      <div className="sr-only">
        <h3>Devices</h3>
        <ul>
          {devices.map((d) => (
            <li key={d.id}>
              <button type="button" onClick={() => select({ kind: "device", id: d.id })}>
                {d.label}, {d.tier ?? d.role ?? "no tier"}, in {nameOf(d.parent ?? "")}
              </button>
            </li>
          ))}
        </ul>
        <h3>Cables</h3>
        <ul>
          {model.cables.map((c) => (
            <li key={c.id}>
              {nameOf(c.from.dev)} {c.from.port ?? ""} to {nameOf(c.to.dev)} {c.to.port ?? ""}
            </li>
          ))}
          {model.exits.map((e) => (
            <li key={`${e.dev}|${e.port}|${e.far_dev}`}>
              {nameOf(e.dev)} {e.port ?? ""} to {e.far_name} {e.far_port ?? ""}, outside this drawing
            </li>
          ))}
        </ul>
        {shownBars.length > 0 && (
          <>
            <h3>Segments</h3>
            <ul>
              {shownBars.map((b) => (
                <li key={b.id}>
                  <button type="button" onClick={() => select({ kind: "segment", id: b.id, bd: b.bd, site: b.site, cidr: null })}>
                    {b.text}, segment
                  </button>
                </li>
              ))}
            </ul>
          </>
        )}
        {shownGroups.length > 0 && (
          <>
            <h3>Clients</h3>
            <ul>
              {shownGroups.map((g) => {
                const key = groupKey(g);
                return (
                  <li key={key}>
                    <button
                      type="button"
                      aria-expanded={groups.has(key)}
                      onClick={() => {
                        toggleGroup(key);
                        select({ kind: "clients", id: `cl:${key}`, group: key });
                      }}
                    >
                      {nameOf(g.dev)} {whereText(g)}: {clientsText(groupIn(g, shownBds).count)}
                    </button>
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}

/** The far end in the drawing of each port of device `dev`: a cable's other end, or the far device of an exit. */
function linksOf(model: TopologyModel, dev: string, nameOf: (id: string) => string): Map<string, string> {
  const out = new Map<string, string>();
  for (const c of model.cables) {
    const ends = c.from.dev === dev ? [c.from, c.to] : c.to.dev === dev ? [c.to, c.from] : null;
    if (ends?.[0].port) out.set(ends[0].port, `${nameOf(ends[1].dev)} ${ends[1].port ?? ""}`.trim());
  }
  for (const e of model.exits) if (e.dev === dev && e.port) out.set(e.port, `${e.far_name} ${e.far_port ?? ""}`.trim());
  return out;
}

const isRouted = (e: CyElement) => e.group === "edges" && /\brouted\b/.test(e.classes ?? "");

/** The port tags of the straight cables, placed clear of the device boxes,
 *  the segment bars and their tags, the client badges and each other (tags.ts).
 *  A cable drawn along its ELK route, or to a stub, keeps its tags at a fixed distance. */
function retag(core: cytoscape.Core, look: Look, boxes: ReadonlyMap<string, Box>, measure: Measure) {
  const at = new Map(core.nodes(".device").map((n) => [n.id(), { ...n.position() }] as const));
  const shown = core.edges(".cable").filter((el) => {
    const e = el as cytoscape.EdgeSingular;
    return !e.hasClass("behind") && !(e.hasClass("routed") && e.hasClass("bent")) && at.has(e.source().id()) && at.has(e.target().id());
  });
  const obstacles = core.nodes(".segbar, .segtag, .clientbadge, .clientglyph").map((n) => {
    const b = n.boundingBox({ includeLabels: true });
    return { x0: b.x1, y0: b.y1, x1: b.x2, y1: b.y2 };
  });
  // a tag keeps off the drop lines too: each leg of a drop is a thin box
  core.edges(".segdrop").forEach((el) => {
    const e = el as cytoscape.EdgeSingular;
    const points = [e.sourceEndpoint(), ...(e.segmentPoints() ?? []), e.targetEndpoint()].filter((p) => p && Number.isFinite(p.x));
    for (let i = 1; i < points.length; i++) {
      const [p, q] = [points[i - 1], points[i]];
      obstacles.push({ x0: Math.min(p.x, q.x) - 1, y0: Math.min(p.y, q.y) - 1, x1: Math.max(p.x, q.x) + 1, y1: Math.max(p.y, q.y) + 1 });
    }
  });
  const cables = shown.map((el) => {
    const e = el as cytoscape.EdgeSingular;
    return {
      id: e.id(),
      source: e.source().id(),
      target: e.target().id(),
      sourcePort: String(e.data("sourcePort") ?? ""),
      targetPort: String(e.data("targetPort") ?? ""),
      sourceTag: String(e.data("sourceTag") ?? ""),
      targetTag: String(e.data("targetTag") ?? ""),
    };
  });
  const tagLook = { ports: look.ports, addresses: look.interfaceAddresses, along: look.alongLine };
  const places = placeTags(cables, at, boxes, measure, tagLook, obstacles);
  core.batch(() => {
    core.edges(".cable").forEach((e) => {
      const p = places.get(e.id());
      if (!p) {
        const full = look.interfaceAddresses;
        e.data({
          sourceLabel: look.ports ? String(e.data(full ? "sourceTag" : "sourcePort") ?? "") : "",
          targetLabel: look.ports ? String(e.data(full ? "targetTag" : "targetPort") ?? "") : "",
          sourceOffset: 48,
          targetOffset: 48,
        });
        e.removeClass("parallel");
        return;
      }
      e.data({
        sourceLabel: p.sourceLabel,
        targetLabel: p.targetLabel,
        sourceOffset: p.sourceOffset,
        targetOffset: p.targetOffset,
        sourceMarginX: p.sourceMargin.x,
        sourceMarginY: p.sourceMargin.y,
        targetMarginX: p.targetMargin.x,
        targetMarginY: p.targetMargin.y,
        parallelSource: p.sourceEndpoint,
        parallelTarget: p.targetEndpoint,
      });
      e.toggleClass("parallel", p.sourceEndpoint !== null);
    });
  });
}

/** The way of every cable across the segment row, from where the devices and the bars are now (segrow.ts `behindRow`). */
function rethread(core: cytoscape.Core, row: Row) {
  const elements: CyElement[] = [
    ...core.nodes(".device, .segbar").map((n) => ({ group: "nodes" as const, data: { ...n.data() }, position: { ...n.position() } })),
    ...core.edges(".cable").map((e) => ({ group: "edges" as const, data: { ...e.data() }, classes: e.classes().join(" ") })),
  ];
  core.batch(() => {
    for (const e of behindRow(elements, row)) {
      if (e.group !== "edges") continue;
      const edge = core.$id(String(e.data.id));
      edge.data({ viaWeights: e.data.viaWeights ?? "", viaDistances: e.data.viaDistances ?? "" });
      edge.classes(e.classes ?? "");
    }
  });
}

/** Right-angle routes for the drops of moved devices and bars (segrow.ts
 *  `dropRoutes`): every drop of a moved device, and every drop of a moved bar. */
function reroute(core: cytoscape.Core, nodes: cytoscape.NodeCollection) {
  const bars = new Set(nodes.filter(".segbar").map((n) => n.id()));
  const devices = new Set(nodes.filter(".device").map((n) => n.id()));
  const edges = core.edges(".segdrop").filter((el) => {
    const e = el as cytoscape.EdgeSingular;
    return bars.has(String(e.data("bar"))) || devices.has(e.source().id());
  });
  if (edges.empty()) return;
  const drops = edges.map((el) => {
    const e = el as cytoscape.EdgeSingular;
    const dev = e.source().position();
    const off = endpointOffset(e.data("sourceEndpoint"));
    return { id: e.id(), dev: e.source().id(), start: { x: dev.x + off.x, y: dev.y + off.y }, end: { ...e.target().position() } };
  });
  const routes = dropRoutes(drops);
  core.batch(() => {
    for (const d of drops) {
      const e = core.$id(d.id);
      const classes = e.classes().join(" ");
      const path = dropPath(d.start, d.end, routes.get(d.id) ?? [], /\bmoved\b/.test(classes) ? classes : `${classes} moved`);
      e.data(path.data);
      e.classes(path.classes);
    }
  });
}

/** The whole drawing in view, under the layer controls at the top of the stage. */
function fitView(core: cytoscape.Core) {
  const controls = core.container()?.parentElement?.querySelector<HTMLElement>(".nm-layers");
  const top = controls ? controls.offsetTop + controls.offsetHeight + FIT_PAD / 2 : FIT_PAD;
  const box = core.elements(":visible").boundingBox();
  const width = core.width() - 2 * FIT_PAD;
  const height = core.height() - top - FIT_PAD;
  if (!(box.w > 0 && box.h > 0 && width > 0 && height > 0)) {
    core.fit(undefined, FIT_PAD);
    return;
  }
  const zoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.min(width / box.w, height / box.h)));
  core.viewport({
    zoom,
    pan: { x: FIT_PAD + (width - box.w * zoom) / 2 - box.x1 * zoom, y: top + (height - box.h * zoom) / 2 - box.y1 * zoom },
  });
}

/** The organic layout: the force layout (fcose) relaxes the tiered drawing in
 *  place. */
function relax(core: cytoscape.Core, moved: Record<string, { x: number; y: number }>) {
  const fixed = Object.entries(moved)
    .filter(([id]) => core.$id(id).nonempty())
    .map(([nodeId, position]) => ({ nodeId, position }));
  core
    .layout({
      name: "fcose",
      randomize: false,
      animate: false,
      fit: true,
      padding: FIT_PAD,
      quality: "proof",
      nodeDimensionsIncludeLabels: true,
      idealEdgeLength: 170,
      nodeRepulsion: 18_000,
      nodeSeparation: 120,
      fixedNodeConstraint: fixed.length ? fixed : undefined,
    } as cytoscape.LayoutOptions)
    .run();
}

function DeviceDetails({ device, clients }: { device: TopologyNode; clients: MapClientGroup[] }) {
  // the device map's freshness reading: MapDevice and a device node share the fields
  const asDevice = { ...device, uid: device.id, name: device.label } as unknown as MapDevice;
  const fresh = freshnessLabel(asDevice);
  const ages = tableAges(asDevice);
  return (
    <dl>
      {fresh && (
        <>
          <dt>Freshness</dt>
          <dd>
            {fresh}
            {ages.length > 0 && <span className="nm-ages"> ({ages.join(", ")})</span>}
          </dd>
        </>
      )}
      {clients.map((g) => (
        <div key={groupKey(g)} className="nm-panel-row">
          <dt>{g.port || g.ssid ? `Clients on ${whereText(g)}` : "Wired clients"}</dt>
          <dd>
            {g.count}
            {g.clients.length > 0 && (
              <ul className="nm-clients">
                {g.clients.map((c) => (
                  <li key={c.uid}>
                    {c.name}
                    {c.ips.length > 0 ? ` ${c.ips.join(", ")}` : ""}
                  </li>
                ))}
                {g.count > g.clients.length && <li>{g.count - g.clients.length} more</li>}
              </ul>
            )}
          </dd>
        </div>
      ))}
      <dt>Tier</dt>
      <dd>{device.tier ?? "none"}</dd>
      <dt>Role</dt>
      <dd>
        {device.role ?? "unknown"}
        {device.role_basis ? `, from ${BASIS_TEXT[device.role_basis] ?? device.role_basis}` : ""}
      </dd>
      {device.block_basis !== undefined && (
        <>
          <dt>Block</dt>
          <dd>from {BASIS_TEXT[device.block_basis] ?? device.block_basis}</dd>
        </>
      )}
      {device.depth !== undefined && (
        <>
          <dt>Hops from the outside</dt>
          <dd>{device.depth ?? "no cable path"}</dd>
        </>
      )}
      {device.vendor && (
        <>
          <dt>Vendor</dt>
          <dd>{device.vendor}</dd>
        </>
      )}
      {device.model && (
        <>
          <dt>Model</dt>
          <dd>{device.model}</dd>
        </>
      )}
    </dl>
  );
}

/** "as of run <time>": clients are what one run collected. */
function asOfRun(snapshot: number | null | undefined): string {
  return snapshot ? `as of run ${new Date(snapshot).toLocaleString()}` : "as of the pinned run";
}

const seenText = (ms: number | null | undefined) => (ms ? new Date(ms).toLocaleString() : "not stated");

/** One segment: what it is, where it is carried and routed, and the full list
 *  of its clients at the drawn sites, a page at a time (GET /topology/segment).
 *  A prefix bar of the L3 layer that no segment holds shows the prefix and the
 *  interfaces on it. */
function SegmentPanel({
  model,
  site,
  bd,
  segSite,
  cidr,
  domain,
  nameOf,
  onClose,
}: {
  model: TopologyModel;
  site: string;
  bd: string | null;
  /** the site of a segment record kept per site, else null */
  segSite: string | null;
  cidr: string | null;
  domain: string | null;
  nameOf: (id: string) => string;
  onClose: () => void;
}) {
  const seg: TopologySegment | undefined = (model.segments ?? []).find((s) => s.bd === bd && (s.site ?? null) === segSite);
  const prefix = cidr ? (model.subnets ?? []).find((s) => s.cidr === cidr && (domain === null || domainKey(s) === domain)) : undefined;
  const [offset, setOffset] = useState(0);
  // a record kept per site reads the clients of its own site only
  const sites = (segSite ? [segSite] : codesOf(site))
    .map((c) => `&site=${encodeURIComponent(c)}`)
    .join("");
  const list = useQuery<SegmentClientsPage>({
    queryKey: ["topology-segment", site, bd, segSite, offset],
    queryFn: () =>
      api<SegmentClientsPage>(`/topology/segment?bd=${encodeURIComponent(bd ?? "")}${sites}&offset=${offset}&limit=${SEGMENT_PAGE}`),
    enabled: !!seg && seg.clients > 0,
  });
  const title = seg ? segmentLabel(seg) : (cidr ?? "Segment");
  const gateways = seg?.gateways ?? [];
  const access = (seg?.carriers ?? []).filter((c) => c.access.length > 0);
  const page = list.data;
  return (
    <aside className="nm-panel nm-panel-wide" aria-label="Segment details">
      <header>
        {title}
        <button type="button" onClick={onClose} aria-label="Close details">Close</button>
      </header>
      <dl>
        {seg?.vid != null && (
          <>
            <dt>VLAN</dt>
            <dd>{seg.vid}</dd>
          </>
        )}
        {seg?.name && (
          <>
            <dt>Name</dt>
            <dd>{seg.name}</dd>
          </>
        )}
        {(seg?.cidrs.length ?? 0) > 0 && (
          <>
            <dt>Prefixes</dt>
            <dd>
              {seg!.cidrs.join(", ")}
              {seg!.cidr_basis === "clients" ? ", from the client addresses" : ""}
            </dd>
          </>
        )}
        {!seg && prefix && (
          <>
            <dt>Prefix</dt>
            <dd>{prefix.cidr}</dd>
            <dt>Interfaces</dt>
            <dd>
              <ul className="nm-clients">
                {prefix.members.map((m) => (
                  <li key={`${m.dev}|${m.iface}|${m.ip}`}>
                    {nameOf(m.dev)} {m.iface} {m.ip}
                    {m.fhrp ? ` (${m.fhrp})` : ""}
                  </li>
                ))}
              </ul>
            </dd>
          </>
        )}
        {gateways.length > 0 && (
          <>
            <dt>Gateway</dt>
            <dd>
              <ul className="nm-clients">
                {gateways.map((g) => (
                  <li key={`${g.dev}|${g.iface}|${g.ip ?? ""}`}>
                    {nameOf(g.dev)} {g.iface}
                    {g.ip ? ` ${g.ip}` : ", no address"}
                    {g.basis === "cidr" ? ", by the prefix" : ""}
                    {g.routes === false ? ", not a gateway for path traces" : ""}
                  </li>
                ))}
              </ul>
            </dd>
          </>
        )}
        {seg && (
          <>
            <dt>Carried on</dt>
            <dd>{seg.carriers.length === 1 ? "1 device" : `${seg.carriers.length} devices`}</dd>
          </>
        )}
        {access.length > 0 && (
          <>
            <dt>Access ports</dt>
            <dd>
              <ul className="nm-clients">
                {access.map((c) => (
                  <li key={c.dev}>
                    {nameOf(c.dev)} {c.access.join(", ")}
                  </li>
                ))}
              </ul>
            </dd>
          </>
        )}
        {seg && (
          <>
            <dt>Clients</dt>
            <dd>
              {seg.clients}, {asOfRun(model.snapshot)}
            </dd>
          </>
        )}
      </dl>
      {list.isError && <p className="banner err">{list.error instanceof Error ? list.error.message : String(list.error)}</p>}
      {page && page.clients.length > 0 && (
        <section className="nm-segment-clients" aria-label="Segment clients">
          <p className="nm-panel-note">
            {page.offset + 1} to {page.offset + page.clients.length} of {page.total}, {asOfRun(page.snapshot)}
          </p>
          <table className="nm-client-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Address</th>
                <th>MAC</th>
                <th>Vendor</th>
                <th>Attached to</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {page.clients.map((c) => (
                <tr key={c.uid}>
                  <td>{c.name}</td>
                  <td>{c.ips.join(", ")}</td>
                  <td>{macText(c.mac)}</td>
                  <td>{c.vendor ?? ""}</td>
                  <td>
                    {c.dev_name ?? c.dev} {c.port ?? c.ssid ?? ""}
                  </td>
                  <td>{seenText(c.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {page.total > SEGMENT_PAGE && (
            <p className="nm-panel-actions">
              <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - SEGMENT_PAGE))}>
                Previous
              </button>{" "}
              <button type="button" disabled={offset + SEGMENT_PAGE >= page.total} onClick={() => setOffset(offset + SEGMENT_PAGE)}>
                Next
              </button>
            </p>
          )}
        </section>
      )}
    </aside>
  );
}

/** The clients of one attachment point in the shown segments: the first of
 *  them with their MAC, vendor and last seen, and the full list of each of
 *  their segments one click away. */
function ClientsPanel({
  group,
  bds,
  snapshot,
  segments,
  nameOf,
  onSegment,
  onClose,
}: {
  group: MapClientGroup;
  bds: Set<string> | null;
  snapshot: number | null;
  segments: TopologySegment[];
  nameOf: (id: string) => string;
  onSegment: (s: TopologySegment) => void;
  onClose: () => void;
}) {
  const { count, clients } = groupIn(group, bds);
  const theirs = Object.keys(group.by_bd ?? {})
    .filter((bd) => bds === null || bds.has(bd))
    // with one record per site, the record that holds the group's device
    .map((bd) => segments.find((s) => s.bd === bd && s.attachments.some((a) => a.dev === group.dev)) ?? segments.find((s) => s.bd === bd))
    .filter((s): s is TopologySegment => s !== undefined);
  return (
    <aside className="nm-panel nm-panel-wide" aria-label="Client details">
      <header>
        {nameOf(group.dev)} {whereText(group)}
        <button type="button" onClick={onClose} aria-label="Close details">Close</button>
      </header>
      <p className="nm-panel-note">
        {clientsText(count)}, {asOfRun(snapshot)}
        {count > clients.length ? `, first ${clients.length} listed` : ""}
      </p>
      <table className="nm-client-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Address</th>
            <th>MAC</th>
            <th>Vendor</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {clients.map((c) => (
            <tr key={c.uid}>
              <td>{c.name}</td>
              <td>{c.ips.join(", ")}</td>
              <td>{macText(c.mac)}</td>
              <td>{c.vendor ?? ""}</td>
              <td>{seenText(c.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {theirs.length > 0 && (
        <p className="nm-panel-actions">
          {theirs.map((s) => (
            <button key={segmentId(s)} type="button" onClick={() => onSegment(s)}>
              All clients of {segmentLabel(s)}
            </button>
          ))}
        </p>
      )}
    </aside>
  );
}

/** A site's connections to the other sites: per site, the lines by kind with
 *  the device pairs that form each boundary, a trace of the pair on request
 *  (POST /sites/trace, up to 64 traces), and both sites
 *  opened as one drawing. */
function Connections({ payload, code, onOpen }: { payload: SiteGraphPayload; code: string; onOpen: (site: string) => void }) {
  const [open, setOpen] = useState<string | null>(null);
  const trace = useMutation({
    mutationFn: (other: string) =>
      api<SiteTraceResponse>("/sites/trace", { method: "POST", body: { src_site: code, dst_site: other } }),
  });
  const byOther = new Map<string, SiteGraphEdge[]>();
  for (const e of payload.edges) {
    if (e.a !== code && e.b !== code) continue;
    const other = e.a === code ? e.b : e.a;
    byOther.set(other, [...(byOther.get(other) ?? []), e]);
  }
  const ambiguous = (payload.ambiguous ?? []).filter((a) => a.site === code);
  if (byOther.size === 0 && ambiguous.length === 0) return null;
  const others = [...byOther.keys()].sort();
  return (
    <section className="nm-connections" aria-label="Connections to other sites">
      <h4>Connections</h4>
      <ul>
        {others.map((other) => {
          const edges = byOther.get(other)!;
          const summary = KIND_ORDER.flatMap((k) => edges.filter((e) => e.kind === k).map((e) => `${e.count} ${KIND_LABEL[k]}`)).join(", ");
          const expanded = open === other;
          return (
            <li key={other}>
              <button type="button" className="linkish" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : other)}>
                {other}: {summary}
              </button>
              {expanded && (
                <div className="nm-connection">
                  <p className="nm-panel-actions">
                    <button type="button" disabled={trace.isPending} onClick={() => trace.mutate(other)}>
                      Trace {code} to {other}
                    </button>{" "}
                    <button type="button" onClick={() => onOpen([code, other].sort().join(","))}>
                      Open both
                    </button>
                  </p>
                  {trace.isSuccess && trace.variables === other && (
                    <p className="nm-verdict">
                      {trace.data.note ??
                        `${trace.data.pairs.filter((p) => outcomeOf(p.result) === "passes").length} of ${trace.data.pairs.length} prefix pairs forwarded, ` +
                          `${trace.data.pairs.filter((p) => outcomeOf(p.result) === "fails").length} not forwarded, ` +
                          `${trace.data.pairs.filter((p) => outcomeOf(p.result) === "open").length} not decided` +
                          (trace.data.truncated ? ` (first ${trace.data.pairs.length} of ${trace.data.total_pairs})` : "")}
                    </p>
                  )}
                  {trace.isError && trace.variables === other && (
                    <p className="banner err">{trace.error instanceof Error ? trace.error.message : String(trace.error)}</p>
                  )}
                  {edges.map((e) => (
                    <div key={e.kind}>
                      <h5>{capital(KIND_LABEL[e.kind])}</h5>
                      <ul className="nm-pairs">
                        {e.pairs.map((pair, i) => {
                          // the pair reads from this site's side
                          const row = describePair(e.kind, pair);
                          const [near, far] = e.a === code ? [row.a, row.b] : [row.b, row.a];
                          return (
                            <li key={i}>
                              {near} to {far}
                              {row.note ? `, ${row.note}` : ""}
                            </li>
                          );
                        })}
                        {e.count > e.pairs.length && <li>{e.count - e.pairs.length} more</li>}
                      </ul>
                    </div>
                  ))}
                </div>
              )}
            </li>
          );
        })}
      </ul>
      {ambiguous.map((a) => (
        <p key={a.kind} className="nm-panel-note">
          {a.count} {KIND_LABEL[a.kind]} with an ambiguous peer address
        </p>
      ))}
    </section>
  );
}
