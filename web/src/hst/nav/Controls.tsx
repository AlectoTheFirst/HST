interface Props {
  /** Flies back to the selection; absent without one. */
  onLocate?: () => void;
  view: "iso" | "top";
  onView(view: "iso" | "top"): void;
  onZoom(factor: number): void;
  onFit(): void;
}

/** The map controls: the 2D and 3D views, zoom and fit. */
export default function Controls({ onLocate, view, onView, onZoom, onFit }: Props) {
  return (
    <div className="hst-controls" role="toolbar" aria-label="Map controls">
      <div className="hst-controls-group">
        <button type="button" aria-label="Locate the selection" disabled={!onLocate} onClick={() => onLocate?.()}>
          <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
            <path fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" d="M21 3L3 10.5l7.5 2.5 2.5 7.5z" />
          </svg>
        </button>
      </div>
      <div className="hst-controls-group">
        <button type="button" aria-pressed={view === "top"} onClick={() => onView("top")}>
          2D
        </button>
        <button type="button" aria-pressed={view === "iso"} onClick={() => onView("iso")}>
          3D
        </button>
      </div>
      <div className="hst-controls-group">
        <button type="button" aria-label="Zoom in" onClick={() => onZoom(1.4)}>
          +
        </button>
        <button type="button" aria-label="Zoom out" onClick={() => onZoom(1 / 1.4)}>
          -
        </button>
        <button type="button" aria-label="Fit the map" onClick={onFit}>
          Fit
        </button>
      </div>
    </div>
  );
}
