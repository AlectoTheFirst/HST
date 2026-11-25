/**
 * The legend row at the bottom of a site diagram and the Options drawer. A
 * segment of the speed scale and a device chip each show or hide their cables
 * or devices. The page applies the choice to the canvas as classes (style.ts).
 */

import type { CSSProperties } from "react";
import {
  CATEGORIES,
  SPEED_BINS,
  UNKNOWN_SPEED_LABEL,
  iconUri,
  speedColor,
  type Category,
  type SpeedKey,
  type SymbolName,
} from "./look";

/** The placement of the devices: tiers top to bottom, relaxed by a force layout, or nested in the site, block and HA
 *  frames. */
export type LayoutKind = "tiered" | "organic" | "blocks";

const LAYOUTS: ReadonlyArray<{ key: LayoutKind; label: string }> = [
  { key: "tiered", label: "Tiered" },
  { key: "organic", label: "Organic" },
  { key: "blocks", label: "Blocks" },
];

export interface Look {
  layout: LayoutKind;
  /** the speed bins and the device groups the legend hides */
  hiddenSpeeds: ReadonlySet<SpeedKey>;
  hiddenCategories: ReadonlySet<Category>;
  addresses: boolean;
  ports: boolean;
  interfaceAddresses: boolean;
  alongLine: boolean;
  speedAsText: boolean;
  frames: boolean;
  routes: boolean;
  /** the segment bars of the tiered layout: the picked VLAN's in L2, every segment of the picked domain in L3 */
  segments: boolean;
  /** the client badges per attachment point */
  clients: boolean;
}

export const DEFAULT_LOOK: Look = {
  layout: "tiered",
  hiddenSpeeds: new Set(),
  hiddenCategories: new Set(),
  addresses: true,
  ports: true,
  interfaceAddresses: true,
  alongLine: true,
  speedAsText: false,
  frames: false,
  routes: false,
  segments: true,
  clients: false,
};

/** The symbol the legend shows beside each device group. */
const CATEGORY_SYMBOL: Readonly<Record<Category, SymbolName>> = { l3: "router", l2: "switch", host: "server", other: "unknown" };

/** The overlays the Options drawer turns on and off as chips. */
const OVERLAYS: ReadonlyArray<{ key: "frames" | "routes" | "segments" | "clients"; label: string }> = [
  { key: "frames", label: "Frames" },
  { key: "routes", label: "Routes" },
  { key: "segments", label: "Segments" },
  { key: "clients", label: "Clients" },
];

type PortLabels = "none" | "port" | "address";

function portLabelsOf(look: Look): PortLabels {
  return !look.ports ? "none" : look.interfaceAddresses ? "address" : "port";
}

/** A row of the Options popover: the name, then a segmented choice of one value. */
function Choice<T extends string>({
  name,
  value,
  options,
  onPick,
}: {
  name: string;
  value: T;
  options: ReadonlyArray<{ key: T; label: string }>;
  onPick: (next: T) => void;
}) {
  return (
    <>
      <span className="nm-opt-name">{name}</span>
      <div className="segs nm-opt-segs" role="radiogroup" aria-label={name}>
        {options.map((o) => (
          <button
            key={o.key}
            type="button"
            role="radio"
            aria-checked={value === o.key}
            className={value === o.key ? "on" : ""}
            onClick={() => onPick(o.key)}
          >
            {o.label}
          </button>
        ))}
      </div>
    </>
  );
}

/** The upper limit of a speed bin as a scale tick: 1.5M, 100M, 1G, 10G. */
export function tickOf(mbps: number): string {
  return mbps >= 1000 ? `${mbps / 1000}G` : `${mbps}M`;
}

function flip<T>(set: ReadonlySet<T>, item: T): Set<T> {
  const next = new Set(set);
  if (next.has(item)) next.delete(item);
  else next.add(item);
  return next;
}

export default function Legend({
  look,
  onLook,
  speedCounts,
  categoryCounts,
  dark,
  unknownColor,
}: {
  look: Look;
  onLook: (next: Look) => void;
  speedCounts: ReadonlyMap<SpeedKey, number>;
  categoryCounts: ReadonlyMap<Category, number>;
  dark: boolean;
  unknownColor: string;
}) {
  const speedButton = (key: SpeedKey, label: string, className: string) => (
    <button
      type="button"
      key={key}
      className={className}
      aria-pressed={!look.hiddenSpeeds.has(key)}
      aria-label={label}
      title={label}
      style={{ "--seg": speedColor(key, dark, unknownColor) } as CSSProperties}
      onClick={() => onLook({ ...look, hiddenSpeeds: flip(look.hiddenSpeeds, key) })}
    >
      <span className="nm-seg-bar" />
      <span className="nm-seg-count">{speedCounts.get(key) ?? 0}</span>
    </button>
  );
  return (
    <aside className="nm-legend" aria-label="Legend">
      <div className="nm-legend-part" role="group" aria-label="Link speed">
        <span className="nm-legend-name">Link speed</span>
        <div className="nm-scale">
          <div className="nm-ticks" aria-hidden="true">
            {SPEED_BINS.slice(0, -1).map((b, i) => (
              <span key={b.key} style={{ left: `${((i + 1) * 100) / SPEED_BINS.length}%` }}>
                {tickOf(b.max)}
              </span>
            ))}
          </div>
          {SPEED_BINS.map((b) => speedButton(b.key, b.label, "nm-seg"))}
        </div>
        <span className="nm-legend-name">{UNKNOWN_SPEED_LABEL}</span>
        {speedButton("unknown", UNKNOWN_SPEED_LABEL, "nm-seg nm-seg-unknown")}
      </div>
      <div className="nm-legend-part" role="group" aria-label="Devices">
        <span className="nm-legend-name">Devices</span>
        {CATEGORIES.map((c) => (
          <button
            type="button"
            key={c.key}
            className="nm-chip"
            aria-pressed={!look.hiddenCategories.has(c.key)}
            onClick={() => onLook({ ...look, hiddenCategories: flip(look.hiddenCategories, c.key) })}
          >
            <img className="nm-symbol" src={iconUri(CATEGORY_SYMBOL[c.key])} alt="" />
            {c.label}
            <span className="nm-count">{categoryCounts.get(c.key) ?? 0}</span>
          </button>
        ))}
      </div>
    </aside>
  );
}

/** The drawer with the layout, the labels and the overlays of the drawing. */
export function Options({ look, onLook, onClose }: { look: Look; onLook: (next: Look) => void; onClose: () => void }) {
  return (
    <aside className="nm-options" aria-label="Options">
      <header>
        Options
        <button type="button" onClick={onClose} aria-label="Close options">
          Close
        </button>
      </header>
      <div className="nm-options-body">
        <Choice
          name="Layout"
          value={look.layout}
          options={LAYOUTS}
          // the blocks layout is a picture of its frames
          onPick={(layout) => onLook({ ...look, layout, frames: layout === "blocks" })}
        />
        <Choice
          name="Devices"
          value={look.addresses ? "address" : "name"}
          options={[
            { key: "name", label: "Name" },
            { key: "address", label: "Name and IP" },
          ]}
          onPick={(v) => onLook({ ...look, addresses: v === "address" })}
        />
        <Choice<PortLabels>
          name="Ports"
          value={portLabelsOf(look)}
          options={[
            { key: "none", label: "None" },
            { key: "port", label: "Name" },
            { key: "address", label: "Name and IP" },
          ]}
          onPick={(v) => onLook({ ...look, ports: v !== "none", interfaceAddresses: v === "address" })}
        />
        <Choice
          name="Port text"
          value={look.alongLine ? "along" : "level"}
          options={[
            { key: "level", label: "Level" },
            { key: "along", label: "Along cable" },
          ]}
          onPick={(v) => onLook({ ...look, alongLine: v === "along" })}
        />
        <Choice
          name="Cables"
          value={look.speedAsText ? "speed" : "none"}
          options={[
            { key: "none", label: "None" },
            { key: "speed", label: "Speed" },
          ]}
          onPick={(v) => onLook({ ...look, speedAsText: v === "speed" })}
        />
        <span className="nm-opt-name">Show</span>
        <div className="segs nm-opt-segs" role="group" aria-label="Show">
          {OVERLAYS.map((o) => (
            <button
              key={o.key}
              type="button"
              aria-pressed={look[o.key]}
              className={look[o.key] ? "on" : ""}
              // the segment bars are part of the tiered layout
              disabled={o.key === "segments" && look.layout !== "tiered"}
              onClick={() => onLook({ ...look, [o.key]: !look[o.key] })}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>
    </aside>
  );
}
