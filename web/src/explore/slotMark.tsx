/** The slot shape of a label, and the label chip that the tree and the picture legend use. */

import { slotColor, type Palette } from "./graphStyle";
import { shapePath } from "./lanes";

export function SlotMark({ slot, palette, size = 12 }: { slot: number; palette: Palette; size?: number }) {
  const other = slot >= 8;
  return (
    <svg className="rt-mark" width={size} height={size} viewBox={`-1 -1 ${size + 2} ${size + 2}`} aria-hidden="true">
      <path
        d={shapePath(slot, size)}
        fill={other ? "none" : slotColor(palette, slot)}
        stroke={other ? palette.muted : "none"}
        strokeDasharray={other ? "2 2" : undefined}
      />
    </svg>
  );
}

export function LabelChip({ label, slot, palette }: { label: string; slot: number; palette: Palette }) {
  const color = slot >= 8 ? palette.muted : slotColor(palette, slot);
  return (
    <span className="label-chip" style={{ "--chip": color } as React.CSSProperties}>
      <SlotMark slot={slot} palette={palette} size={9} />
      {label}
    </span>
  );
}
