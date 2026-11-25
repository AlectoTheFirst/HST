/** Picking a catalog entry preselects its form and does not run it. */

import { useEffect, useState, useId } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import type { QueryCatalog, QueryResult } from "../api/types";
import { QueryForm } from "./QueryForm";
import { ResultCard } from "./ResultCard";
import { CypherEditor } from "./CypherEditor";
import { SearchView } from "./SearchView";
import { SchemaView } from "./SchemaView";
import "./browse.css";
import { useAuth, atLeast } from "../auth";
import { useAiContext, useAiPaneId } from "../ai/context";

// split out of the main bundle: a workspace of trace panes never renders it
import { ObjectQueries } from "./ObjectQueriesSection";
import { rovingKeys, rovingTabIndex } from "../shell/rovingKeys";

type Selection = { kind: "query"; key: string } | { kind: "cypher" };
type Tab = "search" | "schema" | "queries";
const TABS: ReadonlyArray<readonly [Tab, string]> = [["search", "Search"], ["schema", "Schema"], ["queries", "Queries"]];

type RunSpec =
  | { type: "canned"; key: string; params: Record<string, string> }
  | { type: "cypher"; query: string; params?: Record<string, string> };

function runSpec(spec: RunSpec): Promise<QueryResult> {
  return spec.type === "canned"
    ? api<QueryResult>(`/queries/${encodeURIComponent(spec.key)}`, { method: "POST", body: { params: spec.params } })
    : api<QueryResult>("/cypher", {
        method: "POST",
        body: { query: spec.query, params: spec.params ?? {} },
      });
}

export default function ExplorePage({
  queryKey,
  cypher,
  queryParams,
  searchText,
  nodeUid,
  searchNonce,
  queryNonce,
  onAsk,
}: {
  queryKey?: string;
  cypher?: boolean;
  /** The form opens filled in with these parameter values. */
  queryParams?: Record<string, string>;
  /** Sent by the command palette: the text for the Search tab, and the object
   *  to open there. A new `searchNonce` opens the tab again. */
  searchText?: string;
  nodeUid?: string;
  searchNonce?: number;
  /** A new value opens the Queries tab and the form again. */
  queryNonce?: number;
  /** Open a catalog query with params filled in (the pane's open-query). The
   *  node panels offer the queries of an object only when it is set. */
  onAsk?: (queryKey: string, params: Record<string, string>) => void;
} = {}) {
  // ids from useId: two Explore panes can be open at once
  const tabsId = useId();
  const { user } = useAuth();
  const [selection, setSelection] = useState<Selection | null>(null);
  // Search and Schema mount on their first visit.
  const [tab, setTab] = useState<Tab>("queries");
  const [visited, setVisited] = useState<ReadonlySet<Tab>>(() => new Set(["queries"]));
  const [opened, setOpened] = useState<{ uid?: string; text?: string; n: number } | null>(null);
  const [starter, setStarter] = useState<string | null>(null);
  const show = (next: Tab) => { setTab(next); setVisited((v) => (v.has(next) ? v : new Set([...v, next]))); };
  const openNode = (uid: string) => { setOpened((o) => ({ uid, n: (o?.n ?? 0) + 1 })); show("search"); };
  useAiContext(
    useAiPaneId(),
    opened?.uid ? { selection: [{ kind: "graph_node", uid: opened.uid, source: "selection" }] } : null,
  );

  const catalog = useQuery({
    queryKey: ["queries"],
    queryFn: () => api<QueryCatalog>("/queries"),
  });
  const objectPanel = onAsk
    ? (node: { labels: string[]; properties: Record<string, unknown> }) => (
        <ObjectQueries catalog={catalog.data?.queries ?? []} labels={node.labels} properties={node.properties} onAsk={onAsk} />
      )
    : undefined;

  useEffect(() => {
    if (!searchNonce) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setOpened((o) => ({ uid: nodeUid, text: searchText, n: (o?.n ?? 0) + 1 }));
    show("search");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchNonce]);

  // What to run is chosen in shell/SideRail, which sets the pane's query.
  // `queryNonce` changes on each pick, so a pick of the same query fires again.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (queryKey || cypher) setTab("queries");
    if (queryKey) setSelection({ kind: "query", key: queryKey });
    else if (cypher) setSelection({ kind: "cypher" });
  }, [queryKey, cypher, queryNonce]);

  const mutation = useMutation<QueryResult, ApiError, RunSpec>({ mutationFn: runSpec });

  const { reset } = mutation;
  useEffect(() => {
    reset();
  }, [selection, reset]);

  const selectedQuery =
    selection?.kind === "query"
      ? catalog.data?.queries.find((q) => q.key === selection.key)
      : undefined;
  const canOperate = !!user && atLeast(user.role, "operator");
  const isCypher = selection?.kind === "cypher" || (!selection && canOperate);

  const errorMessage = mutation.isError
    ? mutation.error instanceof ApiError
      ? mutation.error.message
      : "query failed"
    : null;

  return (
    <div className="explore-layout">
      <div className="explore-page">
        <div className="tabs" role="tablist" aria-label="Explore views">
          {TABS.map(([key, label], i) => (
            <button key={key} type="button" role="tab" id={`${tabsId}-tab-${key}`} aria-selected={tab === key}
              onKeyDown={rovingKeys("tab")}
              tabIndex={rovingTabIndex(tab === key, i, true)}
              aria-controls={`${tabsId}-panel-${key}`} className={tab === key ? "on" : ""} onClick={() => show(key)}>
              {label}
            </button>
          ))}
        </div>
        {visited.has("search") && (
          <div role="tabpanel" id={`${tabsId}-panel-search`} aria-labelledby={`${tabsId}-tab-search`} hidden={tab !== "search"}>
            <SearchView key={opened?.n ?? 0} initialUid={opened?.uid} initialText={opened?.text} objectPanel={objectPanel} />
          </div>
        )}
        {visited.has("schema") && (
          <div role="tabpanel" id={`${tabsId}-panel-schema`} aria-labelledby={`${tabsId}-tab-schema`} hidden={tab !== "schema"}>
            <SchemaView
              onOpenNode={openNode}
              onOpenCypher={canOperate ? (text) => { setStarter(text); setSelection({ kind: "cypher" }); setTab("queries"); } : undefined}
            />
          </div>
        )}
        <div role="tabpanel" id={`${tabsId}-panel-queries`} aria-labelledby={`${tabsId}-tab-queries`} hidden={tab !== "queries"} className="explore-queries">
        {catalog.isError && (
          <div className="banner err">
            <div className="sub">
              {catalog.error instanceof ApiError ? catalog.error.message : "catalog failed to load"}
            </div>
          </div>
        )}
        {selectedQuery && (
          <QueryForm
            key={`${selectedQuery.key}${JSON.stringify(queryParams ?? null)}#${queryNonce ?? 0}`}
            query={selectedQuery}
            initial={queryParams}
            pending={mutation.isPending}
            onRun={(params) => mutation.mutate({ type: "canned", key: selectedQuery.key, params })}
            onRunCypher={
              user && atLeast(user.role, "operator")
                ? (query, params) => mutation.mutate({ type: "cypher", query, params })
                : undefined
            }
          />
        )}
        {isCypher && (
          <CypherEditor
            key={starter ?? "default"}
            initial={starter ?? undefined}
            pending={mutation.isPending}
            onRun={(query) => mutation.mutate({ type: "cypher", query })}
          />
        )}

        {errorMessage && (
          <div className="banner err">
            <div className="sub">{errorMessage}</div>
          </div>
        )}

        {/* A query that returns scalars has no entities: the card is the table
            alone. Keyed on the run and its status, so a new result starts a new
            view graph and an empty selection. */}
        <ResultCard
          key={`${mutation.submittedAt}:${mutation.status}`}
          result={mutation.data ?? null}
          onOpen={openNode}
          objectPanel={objectPanel}
        />
        </div>
      </div>
    </div>
  );
}
