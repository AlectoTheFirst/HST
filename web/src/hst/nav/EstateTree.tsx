import { useState } from "react";
import { matches, parseQuery } from "../../search/match";
import { areaIcon } from "../render/icons";
import type { Scene } from "../render/scene";
import { tintOf } from "../render/style";

interface Props {
  scene: Scene;
  /** Changes when the scene's rows change, so the tree follows the run. */
  version: number;
  selected: string | null;
  onFocus(uid: string): void;
  /** Whether the tree shows; without it the tree keeps its own state and starts open. */
  open?: boolean;
  onOpen?(open: boolean): void;
}

interface Node {
  uid: string;
  label: string;
  count: number;
  kind: string;
  children: Node[];
}

function icon(kind: string, tint?: number) {
  return (
    <span className="hst-tree-icon" style={tint !== undefined ? { color: `#${tint.toString(16).padStart(6, "0")}` } : undefined}>
      <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" dangerouslySetInnerHTML={{ __html: areaIcon(kind) }} />
    </span>
  );
}

/** The sites of the estate and their blocks, from the site and block rows of Tier 0. */
export function estateTree(scene: Scene): Node[] {
  const sites = new Map<string, Node>();
  for (const row of scene.rows("render_t0")) {
    if (row.kind !== "site") continue;
    const uid = String(row.uid);
    if (uid === "site:unassigned" && Number(row.device_count ?? 0) === 0) continue;
    sites.set(uid, { uid, label: String(row.label ?? uid.replace(/^site:/, "")), count: Number(row.device_count ?? 0), kind: "site", children: [] });
  }
  for (const row of scene.rows("render_t0")) {
    if (row.kind !== "block") continue;
    const uid = String(row.uid);
    const site = scene.siteOf(uid) ?? scene.layout.get(String(row.parent_uid ?? ""))?.parent ?? null;
    const parent = site ? sites.get(site) : undefined;
    parent?.children.push({ uid, label: String(row.label ?? row.block_kind ?? uid), count: Number(row.device_count ?? 0), kind: String(row.block_kind ?? "other"), children: [] });
  }
  const order = (a: Node, b: Node) => a.label.localeCompare(b.label, undefined, { numeric: true });
  const out = [...sites.values()].sort(order);
  for (const s of out) s.children.sort(order);
  return out;
}

/** The estate navigator: sites and their blocks, filtered by a search box; a click flies to the element. */
export default function EstateTree({ scene, version, selected, onFocus, open: shown, onOpen }: Props) {
  const [own, setOwn] = useState(true);
  const open = shown ?? own;
  const setOpen = (value: boolean) => (onOpen ? onOpen(value) : setOwn(value));
  const [query, setQuery] = useState("");
  const [closed, setClosed] = useState<ReadonlySet<string>>(new Set());
  // the shared search grammar (search/match.ts) on each element's label and uid
  const parsed = parseQuery(query);
  const q = parsed.text;
  const hit = (n: Node) => matches(parsed, [n.label, n.uid]);
  const tree = estateTree(scene)
    .map((s) => ({ ...s, children: s.children.filter((b) => !q || hit(b) || hit(s)) }))
    .filter((s) => !q || hit(s) || s.children.length > 0);
  if (!open) {
    return (
      <button type="button" className="hst-tree-open" data-version={version} onClick={() => setOpen(true)}>
        {icon("site")} Estate
      </button>
    );
  }
  return (
    <nav className="hst-tree" aria-label="Estate" data-version={version}>
      <header>
        <span className="hst-tree-title">
          {icon("site")} Global estate
        </span>
        <button type="button" aria-label="Hide the estate" onClick={() => setOpen(false)}>
          Hide
        </button>
      </header>
      <input type="search" aria-label="Search the estate" placeholder="Search estate" value={query} onChange={(e) => setQuery(e.target.value)} />
      <ul role="tree">
        {tree.map((site) => {
          const shut = closed.has(site.uid) && !q;
          return (
            <li key={site.uid} role="treeitem" aria-expanded={!shut} aria-selected={selected === site.uid}>
              <div className="hst-tree-row">
                <button
                  type="button"
                  className="hst-tree-twist"
                  aria-label={shut ? `Open ${site.label}` : `Close ${site.label}`}
                  onClick={() => setClosed((c) => {
                    const next = new Set(c);
                    if (next.has(site.uid)) next.delete(site.uid);
                    else next.add(site.uid);
                    return next;
                  })}
                >
                  {shut ? "+" : "-"}
                </button>
                <button type="button" className="hst-tree-item" onClick={() => onFocus(site.uid)}>
                  {icon("site")}
                  <span>{site.label}</span>
                  <span className="hst-tree-count">{site.count}</span>
                </button>
              </div>
              {!shut && (
                <ul role="group">
                  {site.children.map((block) => (
                    <li key={block.uid} role="treeitem" aria-selected={selected === block.uid}>
                      <button type="button" className="hst-tree-item" onClick={() => onFocus(block.uid)}>
                        {icon(block.kind, tintOf(block.kind))}
                        <span>{block.label}</span>
                        <span className="hst-tree-count">{block.count}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
