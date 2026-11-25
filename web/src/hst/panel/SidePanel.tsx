import { useState } from "react";
import { areaIcon } from "../render/icons";
import { tintOf } from "../render/style";
import { SYMBOLS } from "../render/symbols";
import { useWorkspace } from "../../workspace/WorkspaceContext";
import type { Panel } from "./model";

interface Props {
  panel: Panel;
  onFocus(uid: string): void;
  onClose(): void;
}

const DEVICE_ICON = `<g transform="scale(0.375)">${SYMBOLS.router.replace(/#fff/g, "currentColor")}</g>`;

/** The docked panel of the selected device, block or site. */
export default function SidePanel({ panel, onFocus, onClose }: Props) {
  const [tab, setTab] = useState(0);
  // in the workspace the 2D diagram opens; outside it (the showcase) the camera flies to the area
  const workspace = useWorkspace();
  const diagram = workspace ? panel.diagram : null;
  const current = panel.tabs[Math.min(tab, panel.tabs.length - 1)];
  return (
    <aside className="hst-panel" aria-label={`${panel.title} details`}>
      <header>
        <span className="hst-panel-icon" style={{ color: panel.kind === "block" ? `#${tintOf(panel.icon).toString(16).padStart(6, "0")}` : undefined }}>
          <svg
            viewBox="0 0 24 24"
            width="20"
            height="20"
            aria-hidden="true"
            dangerouslySetInnerHTML={{ __html: panel.icon === "device" ? DEVICE_ICON : areaIcon(panel.icon) }}
          />
        </span>
        <div className="hst-panel-head">
          <h3 title={panel.title}>{panel.title}</h3>
          <p className="hst-panel-sub">{panel.subtitle}</p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close the details">
          Close
        </button>
      </header>
      <div className="hst-panel-tabs" role="tablist">
        {panel.tabs.map((t, i) => (
          <button key={t.name} type="button" role="tab" aria-selected={t === current} onClick={() => setTab(i)}>
            {t.name}
            {t.items ? ` (${t.items.length})` : ""}
          </button>
        ))}
      </div>
      {current.facts && (
        <dl className="hst-panel-facts">
          {current.facts.map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      )}
      {(diagram || panel.topology) && (
        <button
          type="button"
          className="hst-panel-action"
          onClick={() => (diagram ? workspace!.openMap(diagram) : onFocus(panel.topology!))}
        >
          View topology
        </button>
      )}
      {current.items && (
        <ul className="hst-panel-items">
          {current.items.length === 0 && <li className="hint">None</li>}
          {current.items.map((item) => (
            <li key={item.uid}>
              <button type="button" onClick={() => onFocus(item.target ?? item.uid)}>
                <span>{item.label}</span>
                <span className="hst-panel-meta">{item.meta}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </aside>
  );
}
