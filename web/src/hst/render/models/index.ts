import type { SymbolName } from "../symbols";

/** The base shape of a device model; the WebGL backend builds one geometry per shape. */
export type Shape = "box" | "cylinder" | "dome" | "rack" | "cloud";

/** `height` in world units above the band; `inset` the margin inside the device footprint, in grid cells. */
export interface ModelSpec {
  shape: Shape;
  height: number;
  inset: number;
}

export const MODELS: Readonly<Record<SymbolName, ModelSpec>> = {
  router: { shape: "cylinder", height: 0.7, inset: 0.2 },
  sdwan: { shape: "cylinder", height: 0.6, inset: 0.2 },
  loadbalancer: { shape: "cylinder", height: 0.6, inset: 0.25 },
  l3switch: { shape: "box", height: 0.6, inset: 0.12 },
  switch: { shape: "box", height: 0.45, inset: 0.12 },
  controller: { shape: "box", height: 0.6, inset: 0.3 },
  firewall: { shape: "box", height: 1.1, inset: 0.3 },
  unknown: { shape: "box", height: 0.45, inset: 0.3 },
  server: { shape: "rack", height: 1.9, inset: 0.55 },
  ap: { shape: "dome", height: 0.4, inset: 0.75 },
  cloud: { shape: "cloud", height: 1.2, inset: 0.05 },
};

/** Whether a shape is round, so it takes a square base inside the footprint. */
export function round(shape: Shape): boolean {
  return shape !== "box" && shape !== "rack";
}
