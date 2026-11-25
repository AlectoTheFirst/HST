import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent, useMemo } from "react";
import "./hst.css";
import { emptyRequirement } from "../assessments/types";
import { useCurrentUser } from "../auth";
import { watchTheme } from "../explore/graphStyle";
import { useWorkspace } from "../workspace/WorkspaceContext";
import { selectedConnections } from "../applications/flows";
import { http, type Source, type TimelineRun } from "./data/api";
import { MapData, type Sink } from "./data/store";
import ApplicationsLayer, { type CatalogLoader, type TwinFlowSelection } from "./flows/ApplicationsLayer";
import { placeFlows } from "./flows/place";
import { useFlows, type FlowLoader } from "./flows/useFlows";
import ContextSelect from "./layers/ContextSelect";
import LayersMenu from "./layers/LayersMenu";
import Search from "./layers/Search";
import type { Hit } from "./layers/find";
import { transports } from "./layers/tunnels";
import Breadcrumb, { type Crumb } from "./nav/Breadcrumb";
import Controls from "./nav/Controls";
import EstateTree from "./nav/EstateTree";
import Minimap from "./nav/Minimap";
import CableModal, { type Cable, type CableEnd } from "./overlay/CableModal";
import SegmentModal from "./overlay/SegmentModal";
import Overlay, { type Pin } from "./overlay/Overlay";
import { panelOf } from "./panel/model";
import SidePanel from "./panel/SidePanel";
import { FLY_MS, fit, fly, levelOf, pan, zoomAt, zoomOf, type Rect } from "./render/camera";
import { createNullRenderer } from "./render/null";
import { Scene } from "./render/scene";
import { takeHandoff, type Handoff } from "./route/handoff";
import { lanesOf, placeHops, routePoints, type Placed, type Step } from "./route/place";
import Steps from "./route/Steps";
import { pageTheme, tintOf } from "./render/style";
import { DEFAULT_STYLE, type CameraState, type Renderer, type Route, type Style, type Viewport } from "./render/types";
import { subscribe, type Open } from "./timeline/events";
import { timelineModel } from "./timeline/model";
import Timeline from "./timeline/Timeline";

export type RendererFactory = (container: HTMLElement) => Promise<Renderer>;

/** The tiles loaded at port zoom at one time; more are dropped, the ones off screen first. */
export const MAX_TILES = 12;
const TILE_DELAY_MS = 150;
const CLICK_PX = 4;
const START: CameraState = { u: 0, v: 0, zoom: 1 };
const START_VIEWPORT: Viewport = { width: 800, height: 600 };

async function defaultRenderer(container: HTMLElement): Promise<Renderer> {
  const three = await import("./render/three");
  return three.webglAvailable() ? three.createThreeRenderer(container) : createNullRenderer();
}

interface Props {
  source?: Source;
  renderer?: RendererFactory;
  /** Opens the event stream; null leaves the page without live runs. */
  events?: Open | null;
  /** The trace to draw as directions on open; the default takes the Trace pane's handoff from the session. */
  trace?: Handoff | null;
  /** Reads the stored flow overlay of an application at a run; the default calls the flows route. */
  flows?: FlowLoader;
  /** Reads the application catalog for the Applications section; the default calls the catalog route. */
  catalog?: CatalogLoader;
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function nextFrame(fn: () => void): number {
  return typeof requestAnimationFrame === "function" ? requestAnimationFrame(fn) : window.setTimeout(fn, 16);
}

export default function HstMapPage({ source = http, renderer = defaultRenderer, events, trace, flows: flowLoader, catalog }: Props) {
  const canvasRef = useRef<HTMLDivElement>(null);
  const rendererRef = useRef<Renderer | null>(null);
  const dataRef = useRef<MapData | null>(null);
  const cameraRef = useRef<CameraState>(START);
  const viewportRef = useRef<Viewport>(START_VIEWPORT);
  // The estate tree starts hidden; the fit leaves room for it only while it shows.
  const [treeOpen, setTreeOpen] = useState(false);
  const treeRef = useRef(false);
  const frameRef = useRef(0);
  const tileTimer = useRef(0);
  const flight = useRef(0);
  const drag = useRef<{ x: number; y: number; moved: number } | null>(null);
  const [scene] = useState(() => new Scene());
  const [runs, setRuns] = useState<TimelineRun[]>([]);
  const [position, setPosition] = useState(-1);
  const [live, setLive] = useState(-1);
  const [style, setStyle] = useState<Style>(DEFAULT_STYLE);
  /** the style on screen, for a renderer that finishes loading after the style changed */
  const drawnStyleRef = useRef<Style>(DEFAULT_STYLE);
  const [camera, setCamera] = useState<CameraState>(START);
  const [viewport, setViewport] = useState<Viewport>(START_VIEWPORT);
  const [version, setVersion] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [overlay, setOverlay] = useState<{ uid: string; sticky: boolean } | null>(null);
  const [handoff, setHandoff] = useState<Handoff | null>(() => (trace === undefined ? takeHandoff() : trace));
  // The lane of the trace the directions draw; a new trace starts on its first lane.
  const [lane, setLane] = useState(0);
  const [laneTrace, setLaneTrace] = useState(handoff);
  if (laneTrace !== handoff) {
    setLaneTrace(handoff);
    setLane(0);
  }
  const [pinned, setPinned] = useState<Pin | null>(null);
  const [cable, setCable] = useState<{ cables: Cable[]; x: number; y: number } | null>(null);
  const [segment, setSegment] = useState<{ uid: string; device: string } | null>(null);
  // The application flows shown: nothing until an application is picked and a connection toggled.
  const [flowSelection, setFlowSelection] = useState<TwinFlowSelection | null>(null);
  const canReadText = useCurrentUser()?.permissions.includes("interfaces.read") ?? false;
  const workspace = useWorkspace();
  const onRegression = workspace
    ? (before: number, after: number) =>
        workspace.openAssessments(undefined, undefined, {
          title: `Regression ${before} to ${after}`,
          kind: "regression",
          analysis: { before_snapshot: String(before), snapshot: String(after) },
          definition: {
            request: emptyRequirement(),
            intents: [],
            snapshot: String(after),
            mode: "possible",
            freshness_s: 86400,
          },
        })
    : undefined;

  const draw = useCallback(() => {
    if (frameRef.current) return;
    const tick = () => {
      frameRef.current = 0;
      const r = rendererRef.current;
      if (!r) return;
      r.setCamera(cameraRef.current, viewportRef.current);
      if (r.frame().animating) frameRef.current = nextFrame(tick);
    };
    frameRef.current = nextFrame(tick);
  }, []);

  const syncTiles = useCallback(() => {
    window.clearTimeout(tileTimer.current);
    tileTimer.current = window.setTimeout(() => {
      const data = dataRef.current;
      if (!data || levelOf(cameraRef.current.zoom) < 4) return;
      const visible = scene.visibleBlocks(cameraRef.current, viewportRef.current).slice(0, MAX_TILES);
      const loaded = data.tiles();
      const extra = loaded.length + visible.filter((b) => !loaded.includes(b)).length - MAX_TILES;
      loaded.filter((b) => !visible.includes(b)).slice(0, Math.max(0, extra)).forEach((b) => data.dropTile(b));
      for (const block of visible) {
        data.loadTile(block).then(
          () => {
            setVersion((v) => v + 1);
            draw();
          },
          (e) => setError(message(e)),
        );
      }
    }, TILE_DELAY_MS);
  }, [scene, draw]);

  const moveCamera = useCallback(
    (next: CameraState) => {
      cameraRef.current = next;
      setCamera(next);
      draw();
      syncTiles();
    },
    [draw, syncTiles],
  );

  const flyTo = useCallback(
    (target: CameraState) => {
      const start = cameraRef.current;
      const t0 = performance.now();
      const id = ++flight.current;
      const step = () => {
        if (id !== flight.current) return;
        const t = (performance.now() - t0) / FLY_MS;
        moveCamera(fly(start, target, t));
        if (t < 1) nextFrame(step);
      };
      step();
    },
    [moveCamera],
  );

  const measure = useCallback(() => {
    const el = canvasRef.current;
    const box = el?.getBoundingClientRect();
    if (box && box.width > 0 && box.height > 0) {
      viewportRef.current = { width: box.width, height: box.height };
      setViewport(viewportRef.current);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    let r: Renderer | null = null;
    const container = canvasRef.current;
    if (!container) return;
    const tee = (target: Renderer): Sink => ({
      setTier: (name, rows, tile) => {
        scene.setTier(name, rows, tile);
        target.setTier(name, rows, tile);
      },
      applyDelta: (name, changes, tile) => {
        scene.applyDelta(name, changes, tile);
        target.applyDelta(name, changes, tile);
      },
      dropTile: (tile) => {
        scene.dropTile(tile);
        target.dropTile(tile);
      },
    });
    (async () => {
      try {
        r = await renderer(container);
        if (cancelled) {
          r.dispose();
          return;
        }
        rendererRef.current = r;
        r.setStyle(drawnStyleRef.current);
        const data = new MapData(source, tee(r));
        dataRef.current = data;
        const timeline = await source.timeline();
        if (cancelled) return;
        data.setTimeline(timeline);
        setRuns([...data.runs]);
        if (data.chain.length > 0) {
          const last = data.chain.length - 1;
          await data.open(last);
          if (cancelled) return;
          setLive(last);
          setPosition(last);
          measure();
          moveCamera(fitClear(scene.bounds(), viewportRef.current, treeRef.current));
          setVersion((v) => v + 1);
        }
      } catch (e) {
        if (!cancelled) setError(message(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    const resize =
      typeof ResizeObserver === "function"
        ? new ResizeObserver(() => {
            measure();
            draw();
          })
        : null;
    resize?.observe(container);
    const wheel = (e: WheelEvent) => {
      e.preventDefault();
      const box = container.getBoundingClientRect();
      moveCamera(zoomAt(cameraRef.current, viewportRef.current, e.clientX - box.left, e.clientY - box.top, Math.exp(-e.deltaY * 0.0015)));
    };
    container.addEventListener("wheel", wheel, { passive: false });
    return () => {
      cancelled = true;
      resize?.disconnect();
      container.removeEventListener("wheel", wheel);
      window.clearTimeout(tileTimer.current);
      r?.dispose();
      rendererRef.current = null;
      dataRef.current = null;
    };
  }, [source, renderer, scene, measure, moveCamera, draw]);

  const refreshTimeline = useCallback(async () => {
    const data = dataRef.current;
    if (!data) return;
    try {
      data.setTimeline(await source.timeline());
      setRuns([...data.runs]);
    } catch (e) {
      setError(message(e));
    }
  }, [source]);

  useEffect(() => {
    if (events === null || (events === undefined && typeof EventSource === "undefined")) return;
    const refresh = () => void refreshTimeline();
    return subscribe(refresh, events ?? undefined, refresh);
  }, [events, refreshTimeline]);

  useEffect(() => {
    const read = () => setStyle((s) => {
      const theme = pageTheme();
      return s.theme === theme ? s : { ...s, theme };
    });
    read();
    return watchTheme(read);
  }, []);

  // The stored flows of the picked application at the run on screen; a scrub reads each run once.
  const run = position >= 0 ? (runs[position]?.key ?? null) : null;
  const flowState = useFlows(flowSelection?.application ?? null, flowSelection?.revision, run, flowLoader);
  const placedFlows = useMemo(() => {
    const shown = selectedConnections(flowState.data ?? undefined, flowSelection);
    return shown.length ? placeFlows(scene, shown) : null;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flowState.data, flowSelection, version, scene]);
  // The devices on a shown flow stay lit and the others dim; the style the user sets is kept apart from it.
  const drawnStyle = useMemo<Style>(
    () => ({ ...style, highlight: placedFlows && placedFlows.highlight.size > 0 ? placedFlows.highlight : null }),
    [style, placedFlows],
  );

  useEffect(() => {
    drawnStyleRef.current = drawnStyle;
    scene.setStyle(drawnStyle);
    rendererRef.current?.setStyle(drawnStyle);
    draw();
  }, [scene, drawnStyle, draw]);

  const seek = useCallback(
    async (index: number) => {
      const data = dataRef.current;
      if (!data || index < 0 || index >= data.chain.length) return;
      setPosition(index);
      try {
        await data.seek(index);
        setVersion((v) => v + 1);
        draw();
      } catch (e) {
        setError(message(e));
      }
    },
    [draw],
  );

  const goLive = useCallback(() => {
    const data = dataRef.current;
    if (!data) return;
    const last = data.chain.length - 1;
    setLive(last);
    void seek(last);
  }, [seek]);

  const select = useCallback(
    (uid: string | null) => {
      const p = uid ? scene.layout.get(uid) : undefined;
      const device = p?.kind === "port" ? p.parent : p?.kind === "device" ? p.uid : null;
      setStyle((s) => ({ ...s, selected: device, area: null, tunnel: null, transports: new Map() }));
      const data = dataRef.current;
      if (!device || !data) return;
      const block = scene.blockOf(device);
      if (block) {
        data.loadTile(block).then(
          () => {
            setVersion((v) => v + 1);
            draw();
          },
          (e) => setError(message(e)),
        );
      }
      const edges = [...scene.rows("render_t1_edges")];
      if (!edges.some((e) => Number(e.tunnel_count ?? 0) > 0 && (e.a_uid === device || e.b_uid === device))) return;
      data.device(device).then(
        (tier3) => setStyle((s) => (s.selected === device ? { ...s, transports: transports(device, tier3, edges) } : s)),
        (e) => setError(message(e)),
      );
    },
    [scene, draw],
  );

  const focus = useCallback(
    (uid: string | null) => {
      // A segment of the panel's Segments tab opens its client list; it is a table row, not a layout element.
      if (uid && uid.includes("/segment/")) {
        const device = uid.split("/segment/")[0];
        setSegment({ uid, device: String(scene.row("render_t1", device)?.label ?? device) });
        return;
      }
      const p = uid ? scene.layout.get(uid) : undefined;
      const view = cameraRef.current.view;
      if (!uid || !p) {
        select(null);
        flyTo(fitClear(scene.bounds(), viewportRef.current, treeRef.current, view));
        return;
      }
      if (p.kind === "device" || p.kind === "port") {
        select(uid);
        flyTo({ u: p.u + p.w / 2, v: p.v + p.h / 2, zoom: Math.max(zoomOf(4) * 1.4, cameraRef.current.zoom) });
      } else {
        const plate = p.kind === "site" ? scene.layout.get(uid.replace(/^site:/, "plate:")) ?? p : p;
        const area = p.kind === "plate" ? p.parent : p.kind === "site" || p.kind === "block" ? uid : null;
        setStyle((s) => ({ ...s, selected: null, area, tunnel: null, transports: new Map() }));
        flyTo(
          fitClear({ u0: plate.u, v0: plate.v, u1: plate.u + plate.w, v1: plate.v + plate.h }, viewportRef.current, treeRef.current, view),
        );
      }
    },
    [scene, select, flyTo],
  );

  const onPick = useCallback((hit: Hit) => focus(hit.uid), [focus]);

  /** Opens the cable modal for a cable key or a device pair, at screen point (x, y). False when `hit` is neither. */
  const openCable = useCallback(
    (hit: string, x: number, y: number): boolean => {
      const end = (port: unknown, device: unknown): CableEnd => {
        const row = scene.row("render_t2_ports", String(port));
        return {
          port: String(port),
          device: String(scene.row("render_t1", String(device))?.label ?? device),
          name: String(row?.name_short ?? row?.name ?? port),
        };
      };
      const toCable = (id: string, row: Record<string, unknown>): Cable => ({ id, a: end(row.a_port, row.a_dev), b: end(row.b_port, row.b_dev), row });
      const row = scene.row("render_t2_cables", hit);
      if (row) {
        setCable({ cables: [toCable(hit, row)], x, y });
        return true;
      }
      const edge = scene.row("render_t1_edges", hit);
      const data = dataRef.current;
      if (!edge || !data) return false;
      const a = String(edge.a_uid);
      const b = String(edge.b_uid);
      const blocks = [...new Set([scene.blockOf(a), scene.blockOf(b)].filter((x): x is string => x !== null))];
      Promise.all(blocks.map((block) => data.loadTile(block))).then(
        () => {
          const cables = [...scene.rows("render_t2_cables")]
            .filter((r) => (r.a_dev === a && r.b_dev === b) || (r.a_dev === b && r.b_dev === a))
            .map((r) => toCable(String(r.cable_id), r));
          setCable({ cables, x, y });
          setVersion((v) => v + 1);
          draw();
        },
        (e) => setError(message(e)),
      );
      return true;
    },
    [scene, draw],
  );

  const onPointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    drag.current = { x: e.clientX, y: e.clientY, moved: 0 };
    e.currentTarget.setPointerCapture?.(e.pointerId);
  };
  const onPointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (d) {
      const dx = e.clientX - d.x;
      const dy = e.clientY - d.y;
      d.x = e.clientX;
      d.y = e.clientY;
      d.moved += Math.abs(dx) + Math.abs(dy);
      moveCamera(pan(cameraRef.current, viewportRef.current, dx, dy));
      return;
    }
    if (levelOf(cameraRef.current.zoom) < 3) return;
    const box = e.currentTarget.getBoundingClientRect();
    const hit = rendererRef.current?.pick(e.clientX - box.left, e.clientY - box.top) ?? null;
    const isPort = hit ? scene.layout.get(hit)?.kind === "port" : false;
    const device = hit ? (isPort ? scene.layout.get(hit)?.parent ?? null : hit) : null;
    setStyle((s) => (s.hovered === device ? s : { ...s, hovered: device }));
    const loose = isPort && hit !== null && cableOf(scene, hit) === null;
    setOverlay((o) => (o?.sticky ? o : loose && hit ? (o?.uid === hit ? o : { uid: hit, sticky: false }) : null));
  };
  const onPointerUp = (e: ReactPointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    drag.current = null;
    if (!d || d.moved > CLICK_PX) return;
    const box = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - box.left;
    const y = e.clientY - box.top;
    const hit = rendererRef.current?.pick(x, y) ?? null;
    // A tunnel or circuit line opens in the panel and keeps the selection that drew it.
    if (hit?.startsWith("tunnel:") || hit?.startsWith("circuit:")) {
      setStyle((s) => ({ ...s, tunnel: hit }));
      return;
    }
    if (hit && openCable(hit, x, y)) return;
    const kind = hit ? scene.layout.get(hit)?.kind : undefined;
    const cabled = kind === "port" && hit ? cableOf(scene, hit) : null;
    if (cabled && hit) {
      openCable(cabled, x, y);
      select(hit);
      return;
    }
    if (kind === "port" && hit) setOverlay({ uid: hit, sticky: true });
    if (kind === "device" || kind === "port") select(hit);
    else if (hit) focus(hit);
    else select(null);
  };
  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const step = 60;
    const vp = viewportRef.current;
    const moves: Record<string, () => CameraState> = {
      ArrowLeft: () => pan(cameraRef.current, vp, step, 0),
      ArrowRight: () => pan(cameraRef.current, vp, -step, 0),
      ArrowUp: () => pan(cameraRef.current, vp, 0, step),
      ArrowDown: () => pan(cameraRef.current, vp, 0, -step),
      "+": () => zoomAt(cameraRef.current, vp, vp.width / 2, vp.height / 2, 1.25),
      "-": () => zoomAt(cameraRef.current, vp, vp.width / 2, vp.height / 2, 0.8),
    };
    const move = moves[e.key];
    if (move) {
      e.preventDefault();
      moveCamera(move());
    } else if (e.key === "Escape") {
      setOverlay(null);
      setCable(null);
      select(null);
    }
  };

  const model = timelineModel(runs, position, live);
  const plates = [...scene.layout.values()].filter((p) => p.kind === "plate");
  const areas = [...scene.layout.values()]
    .filter((p) => p.kind === "block")
    .map((place) => ({ place, tint: tintOf(scene.row("render_t0", place.uid)?.block_kind) }));
  const chosen = style.selected ?? style.area;
  const trail = breadcrumb(scene, style.selected);
  // The directions: the trace's hops on the map once the layout is in, placed again after each tile load, the
  // route along the cables, and the camera on the route when it first draws.
  const directions: Placed | null = useMemo(() => {
    if (!handoff || runs.length === 0 || position < 0) return null;
    const placed = placeHops(scene, handoff.result, lane);
    // a picked lane with nothing on the map keeps the list, and with it the lane picker
    return placed.steps.length === 0 && lane === 0 ? null : placed;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [handoff, lane, runs.length, position, version, scene]);
  useEffect(() => {
    const routes: Route[] = placedFlows ? [...placedFlows.routes] : [];
    if (directions) routes.push({ id: "trace", state: "trace", points: routePoints(scene, directions.steps) });
    rendererRef.current?.setRoutes(routes);
    draw();
  }, [directions, placedFlows, scene, draw]);
  const clearRoute = useCallback(() => setHandoff(null), []);
  const toStep = useCallback(
    (step: Step) => {
      select(step.device);
      flyTo({ u: step.u, v: step.v, zoom: Math.max(zoomOf(4) * 1.4, cameraRef.current.zoom) });
    },
    [select, flyTo],
  );
  useEffect(() => {
    if (!directions || directions.steps.length === 0) return;
    const us = directions.steps.map((s) => s.u);
    const vs = directions.steps.map((s) => s.v);
    const rect = { u0: Math.min(...us) - 4, v0: Math.min(...vs) - 4, u1: Math.max(...us) + 4, v1: Math.max(...vs) + 4 };
    flyTo(fitClear(rect, viewportRef.current, treeRef.current, cameraRef.current.view));
    // The camera moves to the route one time, when the directions first draw.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [directions !== null]);

  const panel = panelOf(scene, style.selected, style.area, style.tunnel);
  const identities = [...scene.rows("context_identity")];
  const empty = !loading && !error && runs.length === 0;

  return (
    <div className={`hst-map hst-mode-${model.mode}`} data-version={version}>
      <div className="hst-topbar">
        <h2>Hyperspatial Twin</h2>
        {runs.length > 0 && (
          <span className="hst-state" role="status">
            {model.status}
          </span>
        )}
        <Search scene={scene} version={version} onPick={onPick} />
        <ContextSelect identities={identities} value={style.context} onChange={(context) => setStyle((s) => ({ ...s, context }))} />
        <LayersMenu
          changes={style.changes}
          layers={style.layers}
          onChanges={(changes) => setStyle((s) => ({ ...s, changes }))}
          onLayers={(layers) => setStyle((s) => ({ ...s, layers }))}
        >
          <ApplicationsLayer
            run={run}
            selection={flowSelection}
            onSelection={setFlowSelection}
            flows={flowState.data}
            loading={flowState.loading}
            error={flowState.error}
            offMap={placedFlows?.offMap ?? new Map()}
            catalog={catalog}
          />
        </LayersMenu>
      </div>
      <div className="hst-stage">
        {/* The canvas takes pointer and keyboard input for pan, zoom and selection. */}
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions */}
        <div
          ref={canvasRef}
          className="hst-map-canvas"
          role="application"
          aria-label="Map canvas"
          // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
          tabIndex={0}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onKeyDown={onKeyDown}
        />
        {runs.length > 0 && !directions && (
          <EstateTree
            scene={scene}
            version={version}
            selected={chosen}
            onFocus={focus}
            open={treeOpen}
            onOpen={(open) => {
              treeRef.current = open;
              setTreeOpen(open);
            }}
          />
        )}
        {directions && handoff && (
          <Steps
            steps={directions.steps}
            offMap={directions.offMap}
            detail={handoff.result.detail}
            onStep={toStep}
            onClose={clearRoute}
            lanes={lanesOf(handoff.result)}
            lane={lane}
            onLane={setLane}
          />
        )}
        {runs.length > 0 && <Breadcrumb trail={trail} onSelect={focus} />}
        {overlay && position >= 0 && runs[position] && (
          <Overlay
            source={source}
            uid={overlay.uid}
            run={runs[position].key}
            runLabel={model.ticks[position]?.label ?? String(runs[position].key)}
            canReadText={canReadText}
            pinned={pinned}
            onPin={setPinned}
            onClose={() => setOverlay(null)}
            onRegression={onRegression}
          />
        )}
        {cable && position >= 0 && runs[position] && (
          <CableModal
            source={source}
            cables={cable.cables}
            run={runs[position].key}
            previous={runs[position].parent}
            canReadText={canReadText}
            x={cable.x}
            y={cable.y}
            onClose={() => setCable(null)}
          />
        )}
        {segment && position >= 0 && runs[position] && (
          <SegmentModal
            source={source}
            uid={segment.uid}
            run={runs[position].key}
            device={segment.device}
            onClose={() => setSegment(null)}
          />
        )}
        {panel && (
          <SidePanel
            key={panel.uid}
            panel={panel}
            onFocus={focus}
            onClose={() => {
              if (style.tunnel) setStyle((s) => ({ ...s, tunnel: null }));
              else select(null);
            }}
          />
        )}
        {runs.length > 0 && (
          <Controls
            onLocate={chosen ? () => focus(chosen) : undefined}
            view={camera.view ?? "iso"}
            onView={(view) => moveCamera({ ...cameraRef.current, view })}
            onZoom={(factor) => {
              const vp = viewportRef.current;
              moveCamera(zoomAt(cameraRef.current, vp, vp.width / 2, vp.height / 2, factor));
            }}
            onFit={() => flyTo(fitClear(scene.bounds(), viewportRef.current, treeRef.current, cameraRef.current.view))}
          />
        )}
        <Minimap plates={plates} areas={areas} camera={camera} viewport={viewport} onJump={(u, v) => moveCamera({ ...cameraRef.current, u, v })} />
      </div>
      {loading && <p className="hint">Loading the map</p>}
      {error && (
        <p className="hst-error" role="alert">
          {error}
        </p>
      )}
      {empty && <p className="hint">No run loaded</p>}
      {runs.length > 0 && <Timeline runs={runs} position={position} live={live} onSeek={(i) => void seek(i)} onLive={goLive} />}
    </div>
  );
}

/** The cable key of the cable `port` is an end of, or null for a port without a loaded cable. */
function cableOf(scene: Scene, port: string): string | null {
  for (const c of scene.rows("render_t2_cables")) if (c.a_port === port || c.b_port === port) return String(c.cable_id);
  return null;
}

/** The width the estate tree takes on the left of a wide map. */
const TREE_PX = 270;
const WIDE_PX = 900;

/** `fit` into the part of the viewport the estate tree leaves free while it shows. */
function fitClear(r: Rect, vp: Viewport, tree: boolean, view?: CameraState["view"]): CameraState {
  const inset = tree && vp.width > WIDE_PX ? TREE_PX : 0;
  return pan(fit(r, { width: vp.width - inset, height: vp.height }, view), vp, inset / 2, 0);
}

function breadcrumb(scene: Scene, selected: string | null): Crumb[] {
  const trail: Crumb[] = [{ uid: null, label: "Estate" }];
  if (!selected) return trail;
  const site = scene.siteOf(selected);
  const block = scene.blockOf(selected);
  if (site) trail.push({ uid: site, label: String(scene.row("render_t0", site)?.label ?? site.replace(/^site:/, "")) });
  if (block) trail.push({ uid: block, label: String(scene.row("render_t0", block)?.label ?? block) });
  trail.push({ uid: selected, label: String(scene.row("render_t1", selected)?.label ?? selected) });
  return trail;
}
