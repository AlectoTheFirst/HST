/**
 * The persistent left rail.
 */

import { useState } from "react";
import { useWorkspace } from "../workspace/WorkspaceContext";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAuth } from "../auth";
import { readJson, writeJson } from "./storage";
import { useHealth } from "./useHealth";
import { MAX_PANES, panes, type PaneView } from "../workspace/layout";
import { LISTED_VIEWS, VIEWS } from "../workspace/views";
import { type CannedQuery, type QueryCatalog, viewHasData } from "../api/types";
import { Icon } from "./icons";

const COLLAPSE_KEY = "hst-rail-collapsed";
/** Whether the rail is narrowed to its icons. */
const MINI_KEY = "hst-rail-mini";


/** Group by `group`, preserving each group's first-seen order in the catalog. */
function groupCatalog(queries: CannedQuery[]): Array<[string, CannedQuery[]]> {
  const order: string[] = [];
  const byGroup = new Map<string, CannedQuery[]>();
  for (const q of queries) {
    if (!byGroup.has(q.group)) {
      byGroup.set(q.group, []);
      order.push(q.group);
    }
    byGroup.get(q.group)!.push(q);
  }
  return order.map((g) => [g, byGroup.get(g)!]);
}

/** Consecutive entries with one section, in order; entries without one have
 *  the section "". */
function sections(queries: CannedQuery[]): [string, CannedQuery[]][] {
  const out: [string, CannedQuery[]][] = [];
  for (const q of queries) {
    const section = q.section ?? "";
    const last = out[out.length - 1];
    if (last && last[0] === section) last[1].push(q);
    else out.push([section, [q]]);
  }
  return out;
}

export function SideRail() {
  const { user } = useAuth();
  const health = useHealth();

  const catalog = useQuery({
    queryKey: ["queries"],
    queryFn: () => api<QueryCatalog>("/queries"),
    enabled: !!user,
  });

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() =>
    readJson<Record<string, boolean>>(COLLAPSE_KEY, {}),
  );
  const [mini, setMini] = useState<boolean>(() => readJson<boolean>(MINI_KEY, false));

  // AppShell renders the rail inside its WorkspaceProvider, always
  const workspace = useWorkspace()!;

  function toggleMini() {
    setMini((m) => {
      writeJson(MINI_KEY, !m);
      return !m;
    });
  }

  function openView(view: PaneView) {
    VIEWS.find((v) => v.view === view)?.open(workspace);
  }

  function open(queryKey?: string, cypher?: boolean) {
    workspace.openQuery(queryKey, cypher);
  }

  const paneCount = panes(workspace.state.root).length;
  const focusedPane = panes(workspace.state.root).find((p) => p.id === workspace.state.focus);

  function paneAction(action: { type: "split"; dir: "row" | "col" } | { type: "close" }) {
    workspace.dispatch({ ...action, id: workspace.state.focus });
  }

  const activeKey = focusedPane?.view === "explore" ? focusedPane.queryKey : undefined;

  const groups = groupCatalog(catalog.data?.queries ?? []);
  const activeGroup = groups.find(([, qs]) => qs.some((q) => q.key === activeKey))?.[0];

  function isCollapsed(group: string): boolean {
    if (group in collapsed) return collapsed[group];
    return group !== activeGroup;
  }

  // Opening a group closes every other listed group; closing closes only it.
  function toggle(group: string) {
    const opening = isCollapsed(group);
    setCollapsed((prev) => {
      const next: Record<string, boolean> = { ...prev, [group]: !opening };
      if (opening) for (const [other] of groups) if (other !== group) next[other] = true;
      writeJson(COLLAPSE_KEY, next);
      return next;
    });
    if (opening) {
      const header = document.getElementById(`rail-toggle-${group.replace(/\W+/g, "-")}`);
      header?.scrollIntoView?.({ block: "start" });
    }
  }

  return (
    <nav className={"side-rail" + (mini ? " mini" : "")} aria-label="Navigation">
      <div className="rail-views">
        {LISTED_VIEWS.filter((v) => viewHasData(v.view, catalog.data)).map((v) => {
            const on = focusedPane?.view === v.view;
            return (
              <button
                key={v.view}
                type="button"
                className={"rail-item nav" + (on ? " on" : "")}
                aria-current={on ? "page" : undefined}
                title={mini ? v.label : undefined}
                onClick={() => openView(v.view)}
              >
                <Icon name={v.icon} />
                <span className="rail-label">{v.label}</span>
              </button>
            );
          })}
      </div>
      <div className="rail-library">
      <div className="eyebrow">Cypher library</div>
      {catalog.isLoading && <span className="hint">Loading</span>}
      {catalog.isError && <span className="hint" role="alert">Queries not loaded</span>}

      {groups.map(([group, queries]) => {
        const shut = isCollapsed(group);
        const listId = `rail-group-${group.replace(/\W+/g, "-")}`;
        return (
          <div className="rail-group" key={group}>
            <button
              type="button"
              id={`rail-toggle-${group.replace(/\W+/g, "-")}`}
              className="rail-group-toggle"
              aria-expanded={!shut}
              aria-controls={listId}
              onClick={() => toggle(group)}
            >
              <span className={"rail-chevron" + (shut ? "" : " open")}>
                <Icon name="chevron-right" size={12} />
              </span>
              {queries[0]?.group_title ?? group}
              <span className="rail-count">{queries.length}</span>
            </button>
            <div id={listId} className="rail-group-items" hidden={shut}>
              {sections(queries).map(([section, items]) => {
                const buttons = items.map((q) => (
                  <button
                    key={q.key}
                    type="button"
                    title={q.description || undefined}
                    className={"rail-item q" + (activeKey === q.key ? " on" : "")}
                    onClick={() => open(q.key)}
                  >
                    {q.title}
                  </button>
                ));
                if (!section) return buttons;
                const headingId = `${listId}-${section.replace(/\W+/g, "-")}`;
                return (
                  <div key={section} className="rail-section" role="group" aria-labelledby={headingId}>
                    <div id={headingId} className="rail-section-label">
                      {section}
                    </div>
                    {buttons}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      </div>

      <div className="rail-foot">
        <div className="rail-paneactions" role="group" aria-label="Pane actions">
          <button
            type="button"
            className="ws-paneaction"
            title="Split side by side"
            aria-label="Split side by side"
            disabled={paneCount >= MAX_PANES}
            onClick={() => paneAction({ type: "split", dir: "row" })}
          >
            <Icon name="split-row" />
          </button>
          <button
            type="button"
            className="ws-paneaction"
            title="Split stacked"
            aria-label="Split stacked"
            disabled={paneCount >= MAX_PANES}
            onClick={() => paneAction({ type: "split", dir: "col" })}
          >
            <Icon name="split-col" />
          </button>
          <button
            type="button"
            className="ws-paneaction"
            title="Close pane"
            aria-label="Close pane"
            disabled={paneCount <= 1}
            onClick={() => paneAction({ type: "close" })}
          >
            <Icon name="close" />
          </button>
        </div>
        <button
          type="button"
          className="rail-item rail-reset"
          onClick={() => workspace.dispatch({ type: "reset" })}
        >
          Reset workspace
        </button>
        <div className="rail-footrow">
          {health.data?.version && (
            <span className="rail-version">
              v{health.data.version}
              {health.data.revision && health.data.revision !== "unknown"
                ? ` ${health.data.revision.slice(0, 7)}`
                : ""}
            </span>
          )}
          <button
            type="button"
            className="rail-item rail-mini"
            aria-pressed={mini}
            aria-label={mini ? "Expand navigation" : "Collapse navigation"}
            title={mini ? "Expand navigation" : "Collapse navigation"}
            onClick={toggleMini}
          >
            <Icon name={mini ? "expand" : "collapse"} />
            <span className="rail-label">Collapse</span>
          </button>
        </div>
      </div>
    </nav>
  );
}
