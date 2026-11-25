/**
 * The page context a HST AI question carries (`strata/ai/page-context/v1`).
 *
 * Pages publish what they hold in local state through `useAiContext`: the
 * submitted trace, the selected hop, the snapshot on screen, the finding in
 * view. The drawer and the change-simulation chat read one merged
 * `PageContext` through `useAiPageContext`: the route, the focused pane's view
 * and ids from the workspace, and what the pages of that pane registered.
 * Only the focused pane is read.
 *
 * Nothing here is trusted by the server. It checks every reference against the
 * turn's snapshot and the caller's permissions before the model reads it
 * (src/hst/app/ai/context_resolver.py). The values are trimmed to the
 * schema's caps.
 */

import { createContext, useContext, useEffect, useId, useMemo, useState, type ReactNode } from "react";
import { useLocation } from "react-router";
import type {
  PageContext,
  PageContextAnalysisSession,
  PageContextApplication,
  PageContextApplicationDraft,
  PageContextAssessment,
  PageContextFlow,
  PageContextSelection,
  PageContextSelectionKind,
  PageContextSimulation,
  PageContextSnapshot,
} from "../api/types";
import { formatSnapshotDate } from "../flowdesk/SnapshotPicker";
import { panes, type Pane, type Workspace } from "../workspace/layout";
import { VIEW_LABEL } from "../workspace/views";
import { useWorkspace, WORKSPACE_ROUTE } from "../workspace/WorkspaceContext";

/** What one page publishes: every part of a `PageContext` except the route,
 *  which the reader takes from the router, plus the page's own section. */
export interface AiContextFragment {
  section?: string;
  selection?: PageContextSelection[];
  snapshot?: PageContextSnapshot;
  flow?: PageContextFlow;
  simulation?: PageContextSimulation;
  assessment?: PageContextAssessment;
  application?: PageContextApplication;
  analysis_session?: PageContextAnalysisSession;
  application_draft?: PageContextApplicationDraft;
}

interface Registration {
  /** The pane the page renders in; null for a page outside the workspace. */
  paneId: string | null;
  fragment: AiContextFragment;
}

interface Registry {
  set: (token: string, paneId: string | null, fragment: AiContextFragment) => void;
  remove: (token: string) => void;
}

// Pages subscribe to the stable registry only.
const RegistryContext = createContext<Registry | null>(null);
const EntriesContext = createContext<ReadonlyMap<string, Registration> | null>(null);
const PaneContext = createContext<string | null>(null);

/** Holds the registrations. Sits inside `WorkspaceProvider` (shell/AppShell.tsx). */
export function AiContextProvider({ children }: { children: ReactNode }) {
  const [entries, setEntries] = useState<ReadonlyMap<string, Registration>>(() => new Map());
  const registry = useMemo<Registry>(
    () => ({
      // an update keeps the entry's place, so the merge order is the order in
      // which the pages first registered
      set: (token, paneId, fragment) => setEntries((prev) => new Map(prev).set(token, { paneId, fragment })),
      remove: (token) =>
        setEntries((prev) => {
          if (!prev.has(token)) return prev;
          const next = new Map(prev);
          next.delete(token);
          return next;
        }),
    }),
    [],
  );
  return (
    <RegistryContext.Provider value={registry}>
      <EntriesContext.Provider value={entries}>{children}</EntriesContext.Provider>
    </RegistryContext.Provider>
  );
}

/** Names the pane its children render in (workspace/Workspace.tsx). */
export function AiPaneScope({ paneId, children }: { paneId: string; children: ReactNode }) {
  return <PaneContext.Provider value={paneId}>{children}</PaneContext.Provider>;
}

/** The id of the pane the calling page renders in, or null outside the workspace. */
export function useAiPaneId(): string | null {
  return useContext(PaneContext);
}

/**
 * Publish `fragment` as the page context of pane `paneId` (null for a page
 * outside the workspace). A null fragment publishes nothing. The registration
 * follows the fragment's content and is removed when the page unmounts.
 * Outside an `AiContextProvider` this does nothing.
 */
export function useAiContext(paneId: string | null, fragment: AiContextFragment | null): void {
  const registry = useContext(RegistryContext);
  const token = useId();
  // keyed by content: pages build a new object on every render
  const key = fragment ? JSON.stringify(fragment) : null;
  useEffect(() => {
    if (!registry) return;
    return () => registry.remove(token);
  }, [registry, token]);
  useEffect(() => {
    if (!registry) return;
    if (key === null) registry.remove(token);
    else registry.set(token, paneId, JSON.parse(key) as AiContextFragment);
  }, [registry, token, paneId, key]);
}

/**
 * The context the next question carries, or null outside an
 * `AiContextProvider`. On the workspace route it describes the focused pane
 * alone; elsewhere it describes the routed page.
 */
export function useAiPageContext(): PageContext | null {
  const entries = useContext(EntriesContext);
  const workspace = useWorkspace()?.state ?? null;
  const { pathname, search } = useLocation();
  return useMemo(
    () => (entries ? pageContext(entries, workspace, pathname, search) : null),
    [entries, workspace, pathname, search],
  );
}

function pageContext(
  entries: ReadonlyMap<string, Registration>,
  workspace: Workspace | null,
  pathname: string,
  search: string,
): PageContext {
  const focused =
    pathname === WORKSPACE_ROUTE && workspace
      ? panes(workspace.root).find((pane) => pane.id === workspace.focus)
      : undefined;
  const paneId = focused?.id ?? null;
  const fragments = [...entries.values()].filter((entry) => entry.paneId === paneId).map((entry) => entry.fragment);
  const merged = fragments.reduce(merge, focused ? paneFragment(focused) : {});
  return clean({
    version: 1,
    route: { pathname, search, pane_id: focused?.id, pane_view: focused?.view, section: merged.section },
    selection: merged.selection,
    snapshot: merged.snapshot,
    flow: merged.flow,
    simulation: merged.simulation,
    assessment: merged.assessment,
    application: merged.application,
    analysis_session: merged.analysis_session,
    application_draft: merged.application_draft,
  });
}

/** The ids the workspace holds for a pane, before its page registers anything. */
function paneFragment(pane: Pane): AiContextFragment {
  const assessment = pane.assessmentId
    ? { assessment_id: pane.assessmentId, run_id: pane.assessmentRunId }
    : undefined;
  if (pane.view === "assessments") return { assessment };
  if (pane.view === "applications") {
    return { application: pane.applicationId ? { application_id: pane.applicationId } : undefined };
  }
  if (pane.view === "analysis") {
    return {
      analysis_session: pane.analysisSessionId ? { id: pane.analysisSessionId } : undefined,
      assessment,
    };
  }
  return {};
}

/** `b` over `a` field by field when both name the same object; `b` alone otherwise. */
function over<T extends object>(a: T | undefined, b: T | undefined, same: (a: T, b: T) => boolean): T | undefined {
  if (!a || !b) return b ?? a;
  if (!same(a, b)) return b;
  return { ...a, ...Object.fromEntries(Object.entries(b).filter(([, value]) => value !== undefined)) } as T;
}

/** A later registration over an earlier one. Selections add up. */
function merge(a: AiContextFragment, b: AiContextFragment): AiContextFragment {
  return {
    section: b.section ?? a.section,
    selection: [...(b.selection ?? []), ...(a.selection ?? [])],
    snapshot: b.snapshot ?? a.snapshot,
    flow: b.flow ?? a.flow,
    simulation: over(a.simulation, b.simulation, () => true),
    assessment: over(a.assessment, b.assessment, (x, y) => x.assessment_id === y.assessment_id),
    application: over(a.application, b.application, (x, y) => x.application_id === y.application_id),
    analysis_session: over(a.analysis_session, b.analysis_session, (x, y) => x.id === y.id),
    application_draft: b.application_draft ?? a.application_draft,
  };
}

// --- the schema's caps ----------------------------------------------------------

const MAX_SELECTION = 8;
const MAX_CONNECTIONS = 50;
/** The draft caps of src/hst/app/ai/context_resolver.py. */
export const MAX_DRAFT_YAML_CHARS = 12_000;
export const MAX_DRAFT_MEMBERS = 40;
const MAX_DRAFT_CANDIDATES = 8;
const MAX_DRAFT_ISSUES = 5;
const MAX_DRAFT_ERRORS = 10;
const MAX_STORE_ID = 2 ** 31 - 1;
// 18 digits always fit the 64-bit run id the server parses
const RUN_ID = /^[0-9]{1,18}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Free text, cut to the cap. */
function cut(value: string | null | undefined, max: number): string | undefined {
  return value ? value.slice(0, max) : undefined;
}

/** An identifier, dropped when it exceeds the cap: a cut id names another object. */
function ident(value: string | null | undefined, max: number): string | undefined {
  return value && value.length <= max ? value : undefined;
}

function storeId(value: number | null | undefined): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= MAX_STORE_ID ? value : undefined;
}

function snapshotRef(ref: PageContextSnapshot | undefined): PageContextSnapshot | undefined {
  if (!ref || !RUN_ID.test(ref.id)) return undefined;
  return {
    id: ref.id,
    origin: ref.origin,
    compare_id: ref.compare_id && RUN_ID.test(ref.compare_id) ? ref.compare_id : undefined,
  };
}

function selectionItems(items: PageContextSelection[] | undefined): PageContextSelection[] | undefined {
  const seen = new Set<string>();
  const out: PageContextSelection[] = [];
  for (const item of items ?? []) {
    const uid = ident(item.uid, 500);
    const key = `${item.kind}:${uid}`;
    if (!uid || seen.has(key)) continue;
    seen.add(key);
    out.push({
      kind: item.kind,
      uid,
      inventory_id: ident(item.inventory_id, 200),
      label: cut(item.label, 200),
      source: item.source,
    });
  }
  return out.length ? out.slice(0, MAX_SELECTION) : undefined;
}

function flowRef(flow: PageContextFlow | undefined): PageContextFlow | undefined {
  if (!flow) return undefined;
  const port = typeof flow.port === "number" ? (Number.isInteger(flow.port) ? flow.port : undefined) : ident(flow.port, 20);
  return { src: ident(flow.src, 200), dst: ident(flow.dst, 200), port, proto: ident(flow.proto, 20), reply: flow.reply };
}

function simulationRef(simulation: PageContextSimulation | undefined): PageContextSimulation | undefined {
  if (!simulation) return undefined;
  const out: PageContextSimulation = {
    conversation_id: simulation.conversation_id && UUID.test(simulation.conversation_id) ? simulation.conversation_id : undefined,
    step_id: simulation.step_id && UUID.test(simulation.step_id) ? simulation.step_id : undefined,
    analysis_session_id: ident(simulation.analysis_session_id, 200),
    analysis_session_revision: storeId(simulation.analysis_session_revision),
    change_id: storeId(simulation.change_id),
  };
  return Object.values(out).some((value) => value !== undefined) ? out : undefined;
}

function assessmentRef(assessment: PageContextAssessment | undefined): PageContextAssessment | undefined {
  const id = ident(assessment?.assessment_id, 200);
  if (!assessment || !id) return undefined;
  return {
    assessment_id: id,
    revision: storeId(assessment.revision),
    run_id: ident(assessment.run_id, 200),
    finding_id: ident(assessment.finding_id, 200),
  };
}

function applicationRef(application: PageContextApplication | undefined): PageContextApplication | undefined {
  const id = ident(application?.application_id, 200);
  if (!application || !id) return undefined;
  const connections = (application.connection_ids ?? []).filter((value) => ident(value, 200)).slice(0, MAX_CONNECTIONS);
  return {
    application_id: id,
    revision: storeId(application.revision),
    connection_ids: connections.length ? connections : undefined,
  };
}

function sessionRef(session: PageContextAnalysisSession | undefined): PageContextAnalysisSession | undefined {
  const id = ident(session?.id, 200);
  return session && id ? { id, revision: storeId(session.revision) } : undefined;
}

/** Free texts, each cut to `max`, at most `count` of them. */
function texts(values: string[] | undefined, count: number, max: number): string[] | undefined {
  const out = (values ?? []).filter(Boolean).slice(0, count).map((value) => value.slice(0, max));
  return out.length ? out : undefined;
}

/** The open draft, with each cut to a cap flagged. */
function draftRef(draft: PageContextApplicationDraft | undefined): PageContextApplicationDraft | undefined {
  if (!draft || !UUID.test(draft.generation_id)) return undefined;
  const yaml = draft.yaml ? draft.yaml.slice(0, MAX_DRAFT_YAML_CHARS) : undefined;
  const members = (draft.members ?? []).flatMap((member) => {
    const path = ident(member.path, 200);
    if (!path) return [];
    const candidates = (member.candidates ?? []).filter((uid) => ident(uid, 500)).slice(0, MAX_DRAFT_CANDIDATES);
    return [{
      path,
      status: member.status,
      phrase: cut(member.phrase, 200),
      uid: ident(member.uid, 500),
      candidates: candidates.length ? candidates : undefined,
      note: cut(member.note, 500),
      issues: texts(member.issues, MAX_DRAFT_ISSUES, 300),
    }];
  });
  return {
    generation_id: draft.generation_id,
    status: draft.status,
    run_id: draft.run_id && RUN_ID.test(draft.run_id) ? draft.run_id : undefined,
    edited: draft.edited,
    yaml,
    yaml_truncated: yaml !== undefined && yaml.length < (draft.yaml ?? "").length ? true : draft.yaml_truncated,
    members: members.length ? members.slice(0, MAX_DRAFT_MEMBERS) : undefined,
    members_truncated: members.length > MAX_DRAFT_MEMBERS ? true : draft.members_truncated,
    errors: texts(draft.errors, MAX_DRAFT_ERRORS, 300),
  };
}

/** The context trimmed to the schema: free text cut to its cap, anything the
 *  server would reject left out. */
function clean(context: PageContext): PageContext {
  const { route } = context;
  return {
    version: 1,
    route: {
      pathname: route.pathname.slice(0, 200),
      search: cut(route.search, 500),
      pane_id: ident(route.pane_id, 20),
      pane_view: route.pane_view,
      section: cut(route.section, 40),
    },
    selection: selectionItems(context.selection),
    snapshot: snapshotRef(context.snapshot),
    flow: flowRef(context.flow),
    simulation: simulationRef(context.simulation),
    assessment: assessmentRef(context.assessment),
    application: applicationRef(context.application),
    analysis_session: sessionRef(context.analysis_session),
    application_draft: draftRef(context.application_draft),
  };
}

// --- page helpers ------------------------------------------------------------------

/** The context of one object a page opens a conversation about
 *  (ai/drawer.tsx): the current path and the page's pane with `fragment`,
 *  trimmed to the schema caps like every other context. */
export function objectContext(
  paneId: string | null,
  workspace: Workspace | null,
  fragment: AiContextFragment,
): PageContext {
  const pane = paneId && workspace ? panes(workspace.root).find((item) => item.id === paneId) : undefined;
  return clean({
    version: 1,
    route: { pathname: window.location.pathname, pane_id: pane?.id, pane_view: pane?.view, section: fragment.section },
    selection: fragment.selection,
    snapshot: fragment.snapshot,
    flow: fragment.flow,
    simulation: fragment.simulation,
    assessment: fragment.assessment,
    application: fragment.application,
    analysis_session: fragment.analysis_session,
    application_draft: fragment.application_draft,
  });
}

/** A device as a selection. It carries the inventory id and the graph uid when
 *  both are known, and the inventory id alone until the graph uid is. */
export function deviceSelection(
  inventoryId: string,
  graphUid: string | null | undefined,
  label: string | null | undefined,
  source: PageContextSelection["source"],
): PageContextSelection {
  return graphUid
    ? { kind: "device", uid: graphUid, inventory_id: inventoryId, label: label || undefined, source }
    : { kind: "inventory_device", uid: inventoryId, label: label || undefined, source };
}

/** The graph uid of the site with code `code`: `site:` and the code's slug, as
 *  src/hst/core/uid.py `site` and `slug` build it. */
export function siteUid(code: string): string {
  const slug = code
    .trim()
    .toLowerCase()
    .replace(/ /g, "-")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `site:${slug}`;
}

/** A site as a selection, by its graph uid. */
export function siteSelection(code: string, name: string | null | undefined): PageContextSelection {
  return { kind: "site", uid: siteUid(code), label: name || code, source: "selection" };
}

// --- chips ---------------------------------------------------------------------------

/** One removable part of a context, as the drawer shows it. */
export interface ContextChip {
  key: string;
  label: string;
}


const KIND_LABEL: Record<PageContextSelectionKind, string> = {
  device: "Device",
  interface: "Interface",
  ip: "Address",
  prefix: "Prefix",
  vrf: "VRF",
  site: "Site",
  link: "Link",
  hop: "Hop",
  service_requirement: "Service requirement",
  graph_node: "Object",
  inventory_device: "Inventory device",
};

/** The page the context describes. It is always sent. */
export function routeLabel(route: PageContext["route"]): string {
  const page = route.pane_view ? VIEW_LABEL[route.pane_view] : route.pathname;
  return route.section ? `${page}, ${route.section}` : page;
}

function snapshotDate(id: string): string {
  return formatSnapshotDate(Number(id));
}

const selectionKey = (item: PageContextSelection) => `selection:${item.kind}:${item.uid}`;
// A removed part comes back when the page shows another one.
const partKey = (part: string, value: unknown) => `${part}:${JSON.stringify(value)}`;
// A removed draft stays removed while the user edits it.
const draftKey = (draft: PageContextApplicationDraft) => `application_draft:${draft.generation_id}`;

export function contextChips(context: PageContext): ContextChip[] {
  const chips: ContextChip[] = [];
  const { snapshot, flow, assessment, application, analysis_session: session, simulation, application_draft: draft } = context;
  if (snapshot) {
    const compare = snapshot.compare_id ? `, compared with ${snapshotDate(snapshot.compare_id)}` : "";
    chips.push({ key: partKey("snapshot", snapshot), label: `Snapshot ${snapshotDate(snapshot.id)}${compare}` });
  }
  if (flow) {
    const service = [flow.proto, flow.port].filter((part) => part !== undefined && part !== null && part !== "").join(" ");
    const label = `Flow ${flow.src ?? "any"} to ${flow.dst ?? "any"}${service ? ` ${service}` : ""}${flow.reply ? " with reply" : ""}`;
    chips.push({ key: partKey("flow", flow), label });
  }
  for (const item of context.selection ?? []) {
    chips.push({ key: selectionKey(item), label: `${KIND_LABEL[item.kind]} ${item.label ?? item.uid}` });
  }
  if (assessment) {
    const parts = [`Assessment ${assessment.assessment_id}`];
    if (assessment.run_id) parts.push(`run ${assessment.run_id}`);
    if (assessment.finding_id) parts.push(`finding ${assessment.finding_id}`);
    chips.push({ key: partKey("assessment", assessment), label: parts.join(", ") });
  }
  if (application) {
    const revision = application.revision ? ` revision ${application.revision}` : "";
    const count = application.connection_ids?.length ?? 0;
    const connections = count ? `, ${count} connection${count === 1 ? "" : "s"}` : "";
    chips.push({ key: partKey("application", application), label: `Application ${application.application_id}${revision}${connections}` });
  }
  if (session) {
    const revision = session.revision ? ` revision ${session.revision}` : "";
    chips.push({ key: partKey("analysis_session", session), label: `Analysis session ${session.id}${revision}` });
  }
  if (simulation) {
    chips.push({ key: partKey("simulation", simulation), label: "Change simulation" });
  }
  if (draft) {
    const run = draft.run_id ? ` at run ${draft.run_id}` : "";
    chips.push({ key: draftKey(draft), label: `Business Application draft${run}` });
  }
  return chips;
}

/** `context` without the parts whose chips the user removed. */
export function withoutChips(context: PageContext, removed: ReadonlySet<string>): PageContext {
  const keep = <T,>(part: string, value: T | undefined) =>
    value !== undefined && !removed.has(partKey(part, value)) ? value : undefined;
  const selection = context.selection?.filter((item) => !removed.has(selectionKey(item)));
  return {
    version: 1,
    route: context.route,
    selection: selection?.length ? selection : undefined,
    snapshot: keep("snapshot", context.snapshot),
    flow: keep("flow", context.flow),
    simulation: keep("simulation", context.simulation),
    assessment: keep("assessment", context.assessment),
    application: keep("application", context.application),
    analysis_session: keep("analysis_session", context.analysis_session),
    application_draft: context.application_draft && !removed.has(draftKey(context.application_draft)) ? context.application_draft : undefined,
  };
}
