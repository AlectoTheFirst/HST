/**
 * The shapes GET /api/path answers with.
 */

import type {
  BidirectionalPathResponse,
  EstateExit,
  Hop,
  Leg,
  PathCompareResponse,
  PathResponse,
  ReplyLane,
} from "../api/types";
import type { AiContextFragment } from "../ai/context";
import type { TraceParams } from "./Composer";
import type { Selection } from "./selection";

/** A response is never both compare and reply. */
export type TraceResult = PathResponse | PathCompareResponse | BidirectionalPathResponse;

/** GET /api/path's shape when both `snapshot` and `snapshot_b` were sent,
 *  narrowed on the "a" key, which no PathResponse carries. */
export function isCompare(data: TraceResult): data is PathCompareResponse {
  return "a" in data;
}

/** GET /api/path's shape when `reply=true` was sent, narrowed on the
 *  "forward" key, which neither a bare PathResponse nor a compare response
 *  carries. */
export function isBidirectional(data: TraceResult): data is BidirectionalPathResponse {
  return "forward" in data;
}

/** One pane of the reply side of a bidirectional answer. */
interface ReplyPane {
  key: string;
  heading: string;
  result: PathResponse;
}

export function replyPanes(data: BidirectionalPathResponse): ReplyPane[] {
  if (!Array.isArray(data.reply)) return [{ key: "reply", heading: "Reply", result: data.reply }];
  return data.reply.map((lane: ReplyLane) => ({
    key: `reply-${lane.forward_leg}`,
    heading: `Reply for ${lane.src_label}`,
    result: lane,
  }));
}

interface InterpretationGroup {
  /** "" stands for no anchor. */
  key: string;
  heading: string;
  result: PathResponse;
}

/**
 * Splits a result into one group per distinct `leg.interpretation.anchor`,
 * each carrying only its own lanes. With one distinct anchor, or no leg with
 * `interpretation`, it returns `null`.
 */
export function groupByInterpretation(result: PathResponse): InterpretationGroup[] | null {
  const anchors = new Set(result.legs.map((l) => l.interpretation?.anchor).filter((a) => a !== undefined));
  if (anchors.size <= 1) return null;

  const order: string[] = [];
  const legsByAnchor = new Map<string, PathResponse["legs"]>();
  for (const leg of result.legs) {
    const key = leg.interpretation?.anchor ?? "";
    let bucket = legsByAnchor.get(key);
    if (!bucket) {
      bucket = [];
      order.push(key);
      legsByAnchor.set(key, bucket);
    }
    bucket.push(leg);
  }

  return order.map((key) => {
    const legs = legsByAnchor.get(key)!;
    const lanes = new Set(legs.map((l) => l.lane));
    const hops = result.hops.filter((h) => lanes.has(h.lane));
    const interp = legs[0].interpretation;
    return {
      key,
      heading: interp ? `Assuming ${interp.src_ip} in ${interp.display}` : key,
      result: { ...result, hops, legs },
    };
  });
}

/** The basis of an estate exit in plain words. */
function exitBasis(exit: EstateExit): string {
  if (exit.basis === "wan-link") {
    const link = exit.wan_link ?? exit.wan_link_uid;
    return link ? `collected WAN link ${link}` : "collected WAN link";
  }
  if (exit.basis === "access-client-default") return "access client's default";
  if (exit.basis === "site-zone") {
    const zone = 'site zone "internet"';
    return exit.site_block ? `${zone} of block ${exit.site_block}` : zone;
  }
  return `basis ${String(exit.basis)}`;
}

/** One estate exit as a line: device, interface, next hop and basis. */
export function exitText(exit: EstateExit): string {
  const device = exit.device ?? exit.device_uid;
  const iface = exit.interface ?? exit.interface_uid;
  const hop = exit.next_hop ? `next-hop ${exit.next_hop}` : "no next hop";
  return [device, iface, hop].filter(Boolean).join(" ") + ` (${exitBasis(exit)})`;
}

/** The estate exits of one leg: its own and its carrier's. */
export function legExits(leg: Leg): EstateExit[] {
  return [leg.left_estate, leg.carrier?.left_estate].filter((e): e is EstateExit => !!e);
}

/** The distinct estate exits a pane states, or none. Only a walk whose
 *  `reach` is "left_estate" or "split" has any, and only those its own legs
 *  carry. */
export function paneExits(result: PathResponse): EstateExit[] {
  if (result.reach !== "left_estate" && result.reach !== "split") return [];
  const seen = new Map<string, EstateExit>();
  for (const exit of result.legs.flatMap(legExits)) seen.set(JSON.stringify(exit), exit);
  return [...seen.values()];
}

export interface TraceRequest extends TraceParams {
  reply: boolean;
}

/** The clicked station, or for a clicked lane the rulebase that decided it:
 *  a lane has no uid of its own. A lane's rulebase carries the label of the
 *  station with that uid, and no label when the trace has no such station. */
export function pickedStation(selection: Selection | null, hops: Hop[]): { uid: string; label?: string } | null {
  if (!selection) return null;
  if (selection.type === "hop") return { uid: selection.data.uid, label: selection.data.label };
  const uid = selection.data.blocking_uid ?? selection.data.fw_uid;
  return uid ? { uid, label: hops.find((hop) => hop.uid === uid)?.label } : null;
}

/** The page context of a submitted trace: the flow as submitted, the run it
 *  was traced on, and the station or lane the user clicked. The composer's
 *  unsubmitted fields are not part of it. */
export function traceContext(
  request: TraceRequest,
  shownSnapshot: string | undefined,
  selection: Selection | null,
  hops: Hop[],
): AiContextFragment {
  // reply replaces the compare pane, so a reply trace compares nothing
  const compareId = request.reply ? undefined : request.compareWith;
  const snapshotId = request.snapshot ?? shownSnapshot;
  const picked = pickedStation(selection, hops);
  return {
    flow: {
      src: request.src,
      dst: request.dst,
      port: request.port || undefined,
      proto: request.proto,
      reply: request.reply,
    },
    snapshot: snapshotId
      ? { id: snapshotId, origin: request.snapshot ? "pinned" : "page-default", compare_id: compareId }
      : undefined,
    selection: picked ? [{ kind: "hop", uid: picked.uid, label: picked.label, source: "selection" }] : undefined,
  };
}
