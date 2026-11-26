/**
 * The workspace views: one record per view, in the order the rail and the
 * palette list them. The pane view type, the label maps, the rail, the palette,
 * the opener and the restore check all read this list.
 * app/ai/context_resolver.py `PaneView` must hold the same ids
 * (views.test.ts checks it).
 */
import type { IconName } from "../shell/icons";
import type { WorkspaceApi } from "./WorkspaceContext";

export const VIEW_IDS = [
  "hst",
  "trace",
  "explore",
  "map",
  "sdwan",
  "equinix",
  "diff",
  "applications",
  "analysis",
  "changesim",
  "assessments",
] as const;

export type PaneView = (typeof VIEW_IDS)[number];

export interface ViewSpec {
  view: PaneView;
  label: string;
  icon: IconName;
  /** Switch the focused pane to this view. */
  open: (workspace: WorkspaceApi) => void;
  /** The section of Analysis this view is, when it is one: the rail and the
   *  palette list Analysis only, and the section bar of the pane opens it. */
  section?: "analysis";
}

export const VIEWS: ReadonlyArray<ViewSpec> = [
  { view: "hst", label: "Hyperspatial Twin", icon: "network", open: (w) => w.openView("hst") },
  { view: "trace", label: "Trace", icon: "trace", open: (w) => w.openView("trace") },
  { view: "explore", label: "Explore", icon: "explore", open: (w) => w.openView("explore") },
  { view: "map", label: "Map", icon: "network", open: (w) => w.openMap() },
  { view: "sdwan", label: "SD-WAN", icon: "sdwan", open: (w) => w.openSdwan() },
  { view: "equinix", label: "Equinix Fabric", icon: "equinix", open: (w) => w.openEquinix() },
  { view: "diff", label: "What changed", icon: "diff", open: (w) => w.openDiff() },
  { view: "applications", label: "Business applications", icon: "applications", open: (w) => w.openApplications() },
  { view: "analysis", label: "Analysis", icon: "analysis", open: (w) => w.dispatch({ type: "open-analysis", id: w.state.focus, restore: true }) },
  { view: "changesim", label: "Change simulation", icon: "changesim", open: (w) => w.openChangeSim(), section: "analysis" },
  { view: "assessments", label: "Assessments", icon: "assessments", open: (w) => w.openAssessments(), section: "analysis" },
];

/** The views the rail and the palette list: Change simulation and Assessments
 *  are sections of Analysis. */
export const LISTED_VIEWS: ReadonlyArray<ViewSpec> = VIEWS.filter((v) => !v.section);

/** The sections of the Analysis pane, in the order its section bar shows them. */
export const ANALYSIS_SECTIONS: ReadonlyArray<ViewSpec> = VIEWS.filter(
  (v) => v.view === "analysis" || v.section === "analysis",
);

export const VIEW_LABEL = Object.fromEntries(VIEWS.map((v) => [v.view, v.label])) as Record<PaneView, string>;

/** Retired pane views and the view that opens in their place. */
export const RETIRED_VIEWS: Readonly<Record<string, PaneView>> = { sites: "map", network: "map" };

/** Whether a stored pane names a view this build knows. */
export function isPaneView(value: unknown): value is PaneView {
  return typeof value === "string" && (VIEW_IDS as readonly string[]).includes(value);
}
