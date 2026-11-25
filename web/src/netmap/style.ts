/**
 * The Cytoscape stylesheet of the network map, in the app's palette
 * (explore/graphStyle.ts reads the palette).
 *
 * A device is its symbol (look.ts) with the hostname and the management
 * address under it. A cable is a straight line in the color of its link
 * speed. The port names are plain text at the line ends. They show only when
 * the zoom makes them readable (`min-zoomed-font-size`).
 *
 * The legend of the page switches the rest with classes: the site, block and
 * HA frames (`bare` hides them), the ELK routes (`bent` draws them), the
 * management addresses (`noaddr`), the port names (`noports`), the tags
 * along the line (`along`), the speed as text (`speedtext`), and the devices and
 * cables it hides (`hid`). The segment bars of the L2 and L3 layers are
 * nodes of the tiered layout (segrow.ts); the client badges are drawn after
 * the layout (segments.ts).
 */

import type { Css, StylesheetJson } from "cytoscape";
import type { Palette } from "../explore/graphStyle";
import { DEVICE_HEIGHT } from "./layout";
import { SPEED_BINS, speedColor } from "./look";
import { LABEL_FONT, LABEL_LINE, TAG_FONT } from "./segrow";
import { CABLE_TAG_FONT } from "./tags";

export const FONT = 'Archivo, system-ui, -apple-system, "Segoe UI", Arial, sans-serif';

/** Class put on everything outside a selected device's own cables. */
export const FADED = "nm-faded";

/** The drawn size of a device symbol. The layout keeps the box of the caption. */
export const SYMBOL_WIDTH = 54;

/** The status colours of the flow overlay (flows.ts): a failure and a part
 *  that is not decided. A canvas cannot resolve a custom property. */
export interface Status {
  bad: string;
  warn: string;
}

export function readStatus(root: HTMLElement = document.documentElement): Status {
  const style = getComputedStyle(root);
  return {
    bad: style.getPropertyValue("--bad").trim() || "#d64545",
    warn: style.getPropertyValue("--warntext").trim() || "#b07d12",
  };
}

export function stylesheet(palette: Palette, status: Status = readStatus()): StylesheetJson {
  const caption = {
    "font-family": FONT,
    color: palette.text,
    "min-zoomed-font-size": 8,
  };
  const frame = (style: Css.Node): Css.Node => ({
    shape: "round-rectangle",
    "background-color": palette.panel,
    "background-opacity": 0,
    "border-color": palette.border,
    "border-width": 1,
    label: "data(label)",
    "text-valign": "top",
    "text-halign": "center",
    "text-margin-y": 22,
    "font-size": 12,
    ...caption,
    color: palette.muted,
    ...style,
  });
  return [
    {
      selector: "node.device",
      style: {
        shape: "round-rectangle",
        width: SYMBOL_WIDTH,
        height: DEVICE_HEIGHT,
        "background-color": palette.accent,
        "background-opacity": 0,
        "background-image": "data(icon)",
        "background-fit": "contain",
        "background-clip": "none",
        "border-width": 0,
        "border-color": palette.accent,
        label: "data(caption)",
        "text-wrap": "wrap",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 3,
        "line-height": 1.25,
        "font-size": 11,
        ...caption,
        "text-background-color": palette.panel2,
        "text-background-opacity": 0.75,
        "text-background-padding": "1px",
      } as unknown as Css.Node,
    },
    { selector: "node.device.noaddr", style: { label: "data(label)" } },
    {
      selector: "node.exit",
      style: {
        shape: "round-rectangle",
        width: "data(width)",
        height: 24,
        "background-opacity": 0,
        "border-style": "dashed",
        "border-width": 1,
        "border-color": palette.muted,
        label: "data(label)",
        "text-valign": "center",
        "font-size": 10,
        ...caption,
        color: palette.muted,
      } as Css.Node,
    },
    { selector: "node.site", style: frame({ "border-width": 1.5, "font-size": 14, color: palette.text }) },
    { selector: "node.block", style: frame({ "border-style": "dashed" }) },
    { selector: "node.group", style: frame({ "border-style": "dotted", "text-margin-y": 18, "font-size": 10 }) },
    {
      selector: "edge.cable",
      style: {
        width: 1.6,
        "line-color": palette.line,
        "curve-style": "straight",
        // the tags as tags.ts placed them: off the symbol and the caption, and clear of each other
        "source-label": "data(sourceLabel)",
        "target-label": "data(targetLabel)",
        "source-text-offset": "data(sourceOffset)",
        "target-text-offset": "data(targetOffset)",
        "source-text-margin-x": "data(sourceMarginX)",
        "source-text-margin-y": "data(sourceMarginY)",
        "target-text-margin-x": "data(targetMarginX)",
        "target-text-margin-y": "data(targetMarginY)",
        "font-size": CABLE_TAG_FONT,
        ...caption,
        "min-zoomed-font-size": 10,
        color: palette.text,
        "text-background-color": palette.panel,
        "text-background-opacity": 1,
        "text-background-padding": "2px",
        "text-border-width": 0,
        // the typings take no data() mapper for these, which Cytoscape accepts
      } as unknown as Css.Edge,
    },
    // the speed bins (look.ts): the color of the line
    ...SPEED_BINS.map((bin) => ({
      selector: `edge.cable.spd-${bin.key}`,
      style: { "line-color": speedColor(bin.key, palette.dark, palette.line) } as Css.Edge,
    })),
    { selector: "edge.cable.noports", style: { "source-label": "", "target-label": "" } as Css.Edge },
    {
      selector: "edge.cable.along",
      style: { "source-text-rotation": "autorotate", "target-text-rotation": "autorotate" } as Css.Edge,
    },
    // a cable beside another between the same two devices: its own line
    {
      selector: "edge.cable.parallel",
      style: { "source-endpoint": "data(parallelSource)", "target-endpoint": "data(parallelTarget)" } as unknown as Css.Edge,
    },
    // the segment bars of the L2 and L3 layers (segrow.ts): the line, the VLAN
    // and the prefixes under its left end, a tag per drop, and the drops
    {
      selector: "node.segbar",
      style: {
        shape: "rectangle",
        width: "data(width)",
        height: 3,
        "background-color": palette.accent,
        "border-width": 0,
        label: "data(label)",
        "text-wrap": "wrap",
        "text-justification": "left",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-x": "data(labelDx)",
        "text-margin-y": 4,
        "line-height": LABEL_LINE / LABEL_FONT,
        "font-size": LABEL_FONT,
        ...caption,
        color: palette.text,
        // a cable that crosses the row runs behind the label
        "text-background-color": palette.panel2,
        "text-background-opacity": 1,
        "text-background-padding": "2px",
        "text-events": "yes",
      } as unknown as Css.Node,
    },
    {
      selector: "node.segtag",
      style: {
        shape: "round-rectangle",
        width: "data(width)",
        height: "data(height)",
        "background-color": palette.panel,
        "border-width": 1,
        "border-color": palette.accent,
        label: "data(label)",
        "text-wrap": "wrap",
        "text-valign": "center",
        "text-halign": "center",
        "line-height": 1.25,
        "font-size": TAG_FONT,
        ...caption,
        color: palette.text,
        events: "no",
      } as unknown as Css.Node,
    },
    // the joint of a first-hop pair: a short line under its routers that its drops leave from
    {
      selector: "node.segjoint",
      style: { shape: "rectangle", width: "data(width)", height: 3, "background-color": palette.accent, "border-width": 0, events: "no" } as Css.Node,
    },
    {
      selector: "node.segtap",
      style: { width: 1, height: 1, "background-opacity": 0, "border-width": 0, events: "no" } as Css.Node,
    },
    {
      selector: "edge.segdrop",
      style: {
        width: 1.2,
        "line-color": palette.accent,
        "curve-style": "straight",
        "source-endpoint": "data(sourceEndpoint)",
        "target-endpoint": "0px 0px",
        events: "no",
      } as unknown as Css.Edge,
    },
    {
      // the ELK route of a drop, or the right-angle route of a moved one
      selector: "edge.segdrop.routed",
      style: {
        "curve-style": "segments",
        "edge-distances": "endpoints",
        "segment-weights": "data(segmentWeights)",
        "segment-distances": "data(segmentDistances)",
      } as unknown as Css.Edge,
    },
    { selector: "edge.segdrop.gateway", style: { width: 1.6 } },
    // the line from a router of a first-hop pair to its end of the joint
    { selector: "edge.segdrop.join", style: { "target-endpoint": "data(targetEndpoint)" } as unknown as Css.Edge },
    {
      selector: "node.clientbadge",
      style: {
        shape: "round-rectangle",
        width: "data(width)",
        height: 16,
        "background-color": palette.panel,
        "border-color": palette.muted,
        "border-width": 1,
        label: "data(label)",
        "text-valign": "center",
        "text-halign": "center",
        "font-size": 9,
        ...caption,
        color: palette.muted2,
      } as Css.Node,
    },
    { selector: "node.clientbadge.open", style: { "border-color": palette.accent } },
    {
      selector: "node.clientglyph",
      style: {
        shape: "ellipse",
        width: 9,
        height: 9,
        "background-color": palette.panel,
        "border-color": palette.accent,
        "border-width": 1.2,
        label: "data(label)",
        "text-wrap": "wrap",
        "text-max-width": "110px",
        "text-valign": "bottom",
        "text-margin-y": 2,
        "line-height": 1.2,
        "font-size": 8,
        ...caption,
        color: palette.muted2,
      } as unknown as Css.Node,
    },
    {
      selector: "edge.cable.speedtext",
      style: { label: "data(speedText)", "text-border-width": 0, color: palette.muted2 } as Css.Edge,
    },
    {
      // the ELK route, when the legend asks for right angles
      selector: "edge.cable.routed.bent",
      style: {
        "curve-style": "segments",
        "edge-distances": "endpoints",
        "source-endpoint": "data(sourceEndpoint)",
        "target-endpoint": "data(targetEndpoint)",
        "segment-weights": "data(segmentWeights)",
        "segment-distances": "data(segmentDistances)",
        // the typings take no data() mapper for these, which Cytoscape accepts
      } as unknown as Css.Edge,
    },
    // level 2: one line per pair of blocks, with its cable count
    {
      selector: "edge.bundle",
      style: {
        display: "none",
        width: 6,
        "line-color": palette.line,
        "curve-style": "straight",
        label: "data(label)",
        "font-size": 30,
        ...caption,
        color: palette.muted2,
        "text-background-color": palette.panel,
        "text-background-opacity": 0.9,
        "text-background-padding": "3px",
      } as Css.Edge,
    },
    { selector: "edge.bundle.on", style: { display: "element" } },
    { selector: "edge.cable.off", style: { display: "none" } },
    // L3: the prefix of a routed link on its cable
    {
      selector: "edge.cable.link",
      style: {
        label: "data(linkPrefix)",
        "font-size": 9,
        ...caption,
        "min-zoomed-font-size": 10,
        color: palette.text,
        "text-background-color": palette.panel,
        "text-background-opacity": 1,
        "text-background-padding": "2px",
        "text-border-width": 0,
      } as Css.Edge,
    },
    { selector: "node.block.overview", style: { "font-size": 34, color: palette.text } },
    { selector: "node.site.overview", style: { "font-size": 40 } },
    // level 4: the member cables of one LAG share a halo; a multi-chassis LAG
    // has the accent, and its join is inferred (hst/diagram/planner.py)
    {
      selector: "edge.cable.lag",
      style: { "underlay-color": palette.line, "underlay-opacity": 0.18, "underlay-padding": 5 } as Css.Edge,
    },
    { selector: "edge.cable.lag-multi", style: { "underlay-color": palette.accent, "underlay-opacity": 0.22 } as Css.Edge },
    { selector: "edge.cable.loose", style: { "line-style": "dashed" } },
    // a device this run did not observe
    { selector: "node.device.stale", style: { "background-image-opacity": 0.45 } as Css.Node },
    // the L2 and L3 layers (overlays.ts): what the layer lights, and what it holds back
    { selector: "edge.cable.ov-both", style: { width: 3, "line-color": palette.accent } },
    { selector: "edge.cable.ov-half", style: { width: 2.4, "line-color": palette.accent, "line-style": "dashed" } },
    { selector: ".ov-off", style: { opacity: 0.25 } },
    { selector: "node.device.ov-on", style: { "border-color": palette.accent, "border-width": 2 } },
    {
      selector: "edge.adjacency",
      style: {
        width: 2,
        "line-color": palette.accent,
        "line-style": "dashed",
        "curve-style": "straight",
        label: "data(label)",
        "font-size": 10,
        ...caption,
        color: palette.muted2,
        "text-background-color": palette.panel,
        "text-background-opacity": 0.85,
      } as Css.Edge,
    },
    // the application flows (flows.ts): never by colour alone; the line style
    // and the device markers carry the state too
    { selector: ".fl-off", style: { opacity: 0.3 } },
    { selector: "node.device.fl-on", style: { "border-color": palette.accent, "border-width": 2 } },
    { selector: "node.device.fl-endpoint", style: { "border-color": palette.text, "border-width": 3 } },
    { selector: "node.device.fl-unknown", style: { "border-color": status.warn, "border-width": 3, "border-style": "dashed" } },
    { selector: "node.device.fl-stop", style: { "border-color": status.bad, "border-width": 5, "border-style": "double" } },
    { selector: "edge.cable.fl-passes", style: { width: 3.4, "line-color": palette.accent } },
    { selector: "edge.cable.fl-fails", style: { width: 3.4, "line-color": status.bad } },
    { selector: "edge.cable.fl-decided", style: { width: 3, "line-color": status.warn } },
    { selector: "edge.cable.fl-open", style: { width: 3, "line-color": status.warn, "line-style": "dashed" } },
    {
      selector: `edge.flow-link`,
      style: {
        width: 2.6,
        "line-style": "dashed",
        "curve-style": "straight",
        label: "data(label)",
        "font-size": 10,
        ...caption,
        color: palette.muted2,
        "text-background-color": palette.panel,
        "text-background-opacity": 0.85,
      } as Css.Edge,
    },
    { selector: "edge.flow-link.fl-passes", style: { "line-color": palette.accent } },
    { selector: "edge.flow-link.fl-fails", style: { "line-color": status.bad } },
    { selector: "edge.flow-link.fl-decided", style: { "line-color": status.warn } },
    { selector: "edge.flow-link.fl-open", style: { "line-color": status.warn, "line-dash-pattern": [3, 5] } as Css.Edge },
    { selector: "edge.flow-link.fl-not-evaluated", style: { "line-color": palette.muted, "line-style": "dotted", width: 2 } },
    // a cable that crosses the segment row (segrow.ts `behindRow`)
    {
      selector: "edge.cable.behind",
      style: { width: 1.2, opacity: 0.45, "source-label": "", "target-label": "", label: "" } as Css.Edge,
    },
    // its way through a gap of the row, from the device centres
    {
      selector: "edge.cable.behind.via",
      style: {
        "curve-style": "segments",
        "edge-distances": "node-position",
        "segment-weights": "data(viaWeights)",
        "segment-distances": "data(viaDistances)",
      } as unknown as Css.Edge,
    },
    // a peer-link or a sync link: same layer, drawn heavier
    { selector: "edge.cable.lateral", style: { width: 2.4 } },
    { selector: "node:selected", style: { "border-width": 2, "border-color": palette.accent } },
    { selector: "node.device:selected", style: { "background-opacity": 0.12 } },
    // the frames off: the boxes still hold their devices, but draw nothing and take no pointer
    {
      selector: "node.site.bare, node.block.bare, node.group.bare",
      style: { "border-width": 0, "text-opacity": 0, events: "no" } as Css.Node,
    },
    { selector: ".hid", style: { display: "none" } },
    { selector: "edge:selected", style: { width: 2.6, "line-color": palette.accent } },
    { selector: `.${FADED}`, style: { opacity: 0.2, "text-opacity": 0 } },
    {
      selector: "core",
      style: { "active-bg-opacity": 0, "selection-box-color": palette.accent } as Css.Core,
    },
  ];
}
