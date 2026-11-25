/**
 * The section bar of the Analysis pane: saved Analysis work, Change simulation
 * and Assessments. The rail and the palette list Analysis only; this bar opens
 * the other two in the same pane.
 */
import { ANALYSIS_SECTIONS, type PaneView } from "./views";
import { useWorkspace } from "./WorkspaceContext";

export function AnalysisSections({ current }: { current: PaneView }) {
  const workspace = useWorkspace();
  if (!workspace) return null;
  return (
    <nav className="tabs analysis-sections" aria-label="Analysis tools">
      {ANALYSIS_SECTIONS.map((v) => (
        <button
          key={v.view}
          type="button"
          className={v.view === current ? "on" : undefined}
          aria-current={v.view === current ? "page" : undefined}
          onClick={() => v.open(workspace)}
        >
          {v.label}
        </button>
      ))}
    </nav>
  );
}
