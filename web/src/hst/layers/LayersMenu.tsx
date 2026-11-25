import type { ReactNode } from "react";
import type { Layers } from "../render/types";

interface Props {
  changes: boolean;
  layers: Layers;
  onChanges(on: boolean): void;
  onLayers(layers: Layers): void;
  /** More sections at the end of the menu: the application flows. */
  children?: ReactNode;
}

const NAMES: [keyof Layers, string][] = [
  ["physical", "Physical"],
  ["l2", "L2"],
  ["l3", "L3"],
];

export default function LayersMenu({ changes, layers, onChanges, onLayers, children }: Props) {
  return (
    <fieldset className="hst-layers">
      <legend>Layers</legend>
      <label>
        <input type="checkbox" checked={changes} onChange={(e) => onChanges(e.target.checked)} />
        Changes since previous run
      </label>
      {NAMES.map(([key, name]) => (
        <label key={key}>
          <input type="checkbox" checked={layers[key]} onChange={(e) => onLayers({ ...layers, [key]: e.target.checked })} />
          {name}
        </label>
      ))}
      {children}
    </fieldset>
  );
}
