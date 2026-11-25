import { Suspense, lazy, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ApiError } from "../api/client";
import { exploreApi, type ExploreNode, type NeighborGroup, type NeighborPage } from "../api/explore";
import type { ResultGraph } from "../api/types";
import { KindChips, PLACEHOLDER, SearchResults, useSearchKeys } from "../search/UnifiedSearch";
import { KINDS, type SearchHit } from "../search/types";
import { useSearch } from "../search/useSearch";
import { RoutesPanel } from "./RoutesPanel";
import { mergeGraphs } from "./graphElements";

export { useDebounced } from "../search/useDebounced";

const GraphView = lazy(() => import("./GraphView"));
const EMPTY: ResultGraph = { nodes: [], relationships: [], truncated: false };
const PAGE = 50;

/** The route table lists the routes from GET /api/explore/route-search. */
const SEARCH_KINDS = KINDS.filter((k) => k !== "route");

export function message(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed";
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "None";
  if (Array.isArray(value)) return value.map(formatValue).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

const groupText = (g: NeighborGroup) => (g.direction === "out" ? `${g.type} to ${g.label ?? "node"}` : `${g.type} from ${g.label ?? "node"}`);

export function SearchView({ initialUid, initialText, objectPanel }: {
  initialUid?: string;
  initialText?: string;
  /** Rendered under the head of the node panel, for the node shown. */
  objectPanel?: (node: { labels: string[]; properties: Record<string, unknown> }) => React.ReactNode;
}) {
  const [text, setText] = useState(initialText ?? "");
  const [history, setHistory] = useState<string[]>(initialUid ? [initialUid] : []);
  const [graph, setGraph] = useState<ResultGraph>(EMPTY);
  const search = useSearch({ text, kinds: SEARCH_KINDS, limit: 25 });
  const q = search.debounced;
  // An address or a prefix is also looked up in the route table of every device.
  const isAddress = /^[0-9a-fA-F.:]+(\/\d{1,3})?$/.test(q) && /[.:]/.test(q);
  const routes = useQuery({
    queryKey: ["explore", "route-search", q],
    queryFn: () => exploreApi.routeSearch(q),
    enabled: isAddress,
  });
  const current = history.at(-1);
  const open = (uid: string) => setHistory((h) => (h.at(-1) === uid ? h : [...h, uid]));
  const openHit = (hit: SearchHit) => {
    const uid = hit.target?.uid ?? hit.uid;
    if (uid) open(uid);
  };
  const keys = useSearchKeys({ items: search.items, onOpen: openHit, onEscape: () => setText("") });
  const addToGraph = (payload: ResultGraph | undefined) => setGraph((g) => mergeGraphs(g, payload));

  return (
    <div className="xb">
      <div className="editorcard xb-search">
        <label className="xb-field" htmlFor={keys.inputId}>
          <span className="eyebrow">Search the graph</span>
        </label>
        <input
          id={keys.inputId} type="search" className="xb-input" value={text} autoComplete="off" spellCheck={false}
          placeholder={PLACEHOLDER}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={keys.onInputKeyDown}
        />
        <KindChips search={search} onPick={keys.focusInput} />
      </div>

      <div className="xb-columns">
        <section className="editorcard xb-results" aria-label="Search results">
          <SearchResults
            search={search} keys={keys} onOpen={openHit} selected={current} label="Hits"
            emptyText={() => "No matching nodes"}
          />
          {isAddress && routes.isError && <div className="banner err"><div className="sub">{message(routes.error)}</div></div>}
          {isAddress && routes.data && routes.data.items.length > 0 && (
            <div className="xb-routes">
              <p className="hint">
                {routes.data.total > routes.data.items.length
                  ? `${routes.data.items.length} of ${routes.data.total} routes`
                  : "Routes"}
              </p>
              <table className="xb-route-table" aria-label="Routes">
                <thead>
                  <tr><th>Device</th><th>VRF</th><th>Prefix</th><th>Next hop</th><th>Protocol</th></tr>
                </thead>
                <tbody>
                  {routes.data.items.map((r, i) => (
                    <tr key={`${r.device_uid}:${r.context_uid ?? r.vrf ?? ""}:${r.prefix}:${r.next_hop ?? ""}:${i}`}>
                      <td>
                        <button type="button" className="linkish" title={r.device_uid} onClick={() => open(r.device_uid)}>
                          {r.device}
                        </button>
                      </td>
                      <td>{r.vrf ?? ""}</td>
                      <td className="mono">{r.prefix}</td>
                      <td className="mono">{[r.next_hop, r.interface].filter(Boolean).join(" via ")}</td>
                      <td>{r.protocol ?? ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {current && (
          <NodePanel key={current} uid={current} canGoBack={history.length > 1}
            onBack={() => setHistory((h) => h.slice(0, -1))}
            onClose={() => setHistory([])}
            onOpen={open} onGraph={addToGraph} objectPanel={objectPanel} />
        )}
      </div>

      {graph.nodes.length > 0 && (
        <div className="xb-graph">
          <div className="xb-graphbar">
            <button type="button" className="secondary" onClick={() => setGraph(EMPTY)}>Clear graph</button>
          </div>
          <Suspense fallback={<div className="hint">Drawing the graph</div>}>
            <GraphView graph={graph} onOpen={open} grows />
          </Suspense>
        </div>
      )}
    </div>
  );
}

function NodePanel({ uid, canGoBack, onBack, onClose, onOpen, onGraph, objectPanel }: {
  uid: string; canGoBack: boolean; onBack: () => void; onClose: () => void;
  onOpen: (uid: string) => void; onGraph: (graph: ResultGraph) => void;
  objectPanel?: (node: { labels: string[]; properties: Record<string, unknown> }) => React.ReactNode;
}) {
  const detail = useQuery({ queryKey: ["explore", "node", uid], queryFn: () => exploreApi.node(uid) });
  const node = detail.data?.node;
  useEffect(() => {
    if (node) onGraph({ nodes: [{ id: node.id, labels: node.labels, properties: { ...node.properties, ...node.bookkeeping } }], relationships: [], truncated: false });
    // The node joins the picture once, when it loads.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node?.id]);
  return (
    <section className="editorcard xb-node" aria-label="Node details">
      <div className="bar">
        <span className="eyebrow">Node</span>
        <span className="xb-actions">
          {canGoBack && <button type="button" className="secondary" onClick={onBack}>Back</button>}
          <button type="button" className="secondary" onClick={onClose}>Close</button>
        </span>
      </div>
      {detail.isPending && <p className="hint" role="status">Loading the node</p>}
      {detail.isError && <div className="banner err"><div className="sub">{message(detail.error)}</div></div>}
      {node && <>
        <div className="xb-nodehead">
          <span className="xb-kind">{node.label ?? "Node"}</span>
          <h2 className="xb-title">{node.name || node.uid}</h2>
          <span className="xb-uid">{node.uid}</span>
        </div>
        {objectPanel?.({ labels: node.labels, properties: node.properties })}
        <Properties node={node} />
        {(node.label === "Device" || node.label === "VrfInstance") && <RoutesPanel uid={node.uid} perVrf={node.label === "Device"} />}
        <h3 className="eyebrow">Relationships</h3>
        {detail.data!.neighbors.length === 0 && <p className="hint">No relationships</p>}
        <ul className="xb-groups">
          {detail.data!.neighbors.map((group) => (
            <Group key={`${group.type}-${group.direction}-${group.label}`} uid={node.uid} group={group} onOpen={onOpen} onGraph={onGraph} />
          ))}
        </ul>
      </>}
    </section>
  );
}

function Properties({ node }: { node: ExploreNode }) {
  const rows = Object.entries(node.properties).filter(([key]) => key !== "uid").sort(([a], [b]) => a.localeCompare(b));
  const bookkeeping = Object.entries(node.bookkeeping);
  return <>
    <dl className="xb-props">
      {rows.map(([key, value]) => (
        <div key={key}><dt>{key}</dt><dd>{formatValue(value)}</dd></div>
      ))}
    </dl>
    {bookkeeping.length > 0 && (
      <details className="xb-bookkeeping">
        <summary>Loader bookkeeping</summary>
        <dl className="xb-props">
          {bookkeeping.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{formatValue(value)}</dd></div>)}
        </dl>
      </details>
    )}
  </>;
}

/** One relationship group of a node: a button that lists its neighbors a page
 *  at a time and adds them to the graph. The Queries graph uses it as well. */
export function Group({ uid, group, onOpen, onGraph }: {
  uid: string; group: NeighborGroup; onOpen: (uid: string) => void; onGraph: (graph: ResultGraph) => void;
}) {
  const [pages, setPages] = useState<NeighborPage[]>([]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const shown = pages.flatMap((p) => p.items);
  const expanded = pages.length > 0;
  async function load() {
    setPending(true); setError(null);
    try {
      const page = await exploreApi.neighbors({
        uid, type: group.type, direction: group.direction, label: group.label ?? undefined, offset: shown.length, limit: PAGE,
      });
      setPages((p) => [...p, page]);
      if (page.graph) onGraph(page.graph);
    } catch (err) {
      setError(err);
    } finally {
      setPending(false);
    }
  }
  return (
    <li className="xb-group">
      <button type="button" className="xb-grouphead" aria-expanded={expanded} disabled={pending}
        onClick={() => (expanded ? setPages([]) : void load())}>
        <span>{groupText(group)}</span>
        <span className="xb-count">{group.count.toLocaleString()}</span>
      </button>
      {error !== null && <div className="banner err"><div className="sub">{message(error)}</div></div>}
      {expanded && (
        <ul className="xb-neighbors">
          {shown.map((n) => (
            <li key={n.uid}>
              <button type="button" className="xb-neighbor" onClick={() => onOpen(n.uid)} title={n.uid}>
                {n.name || n.uid}
              </button>
            </li>
          ))}
          {shown.length < group.count && (
            <li>
              <button type="button" className="secondary" disabled={pending} onClick={() => void load()}>
                {pending ? "Loading" : `Show ${Math.min(PAGE, group.count - shown.length)} more`}
              </button>
            </li>
          )}
        </ul>
      )}
    </li>
  );
}
