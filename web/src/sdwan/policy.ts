/**
 * The cells of the business policy table, from the flat properties of one
 * SdwanPolicyRule (collectors/velocloud.py `_rule_match`, `_rule_action`).
 * An absent property is a field that the rule leaves open, so a cell shows
 * only the fields that have a value.
 */

import type { SdwanPolicyRule } from "../api/types";

/** The route actions, as the collector writes their property prefix. */
export const ROUTE_TARGETS = [
  ["edge2edge", "to edges"],
  ["edge2datacenter", "to data centres"],
  ["edge2cloud", "to the cloud"],
] as const;

function value(rule: SdwanPolicyRule, key: string): string | null {
  const v = rule[key];
  if (v === null || v === undefined || v === "") return null;
  return Array.isArray(v) ? v.join(", ") : String(v);
}

function joined(parts: Array<string | null>): string {
  return parts.filter(Boolean).join("; ");
}

/** The match, or "any" when the rule matches all traffic. */
export function matchCell(rule: SdwanPolicyRule): string {
  const extra = joined([
    value(rule, "match_src_interface") && `from ${value(rule, "match_src_interface")}`,
    value(rule, "match_dst_interface") && `to ${value(rule, "match_dst_interface")}`,
    value(rule, "match_src_vlan") && `src vlan ${value(rule, "match_src_vlan")}`,
    value(rule, "match_dst_vlan") && `dst vlan ${value(rule, "match_dst_vlan")}`,
    value(rule, "match_ip_version") && `${value(rule, "match_ip_version")}`,
  ]);
  const summary = value(rule, "match_summary") ?? "any";
  return extra ? `${summary}; ${extra}` : summary;
}

/** The QoS class and the scheduler priority, with the bandwidth caps. */
export function qosCell(rule: SdwanPolicyRule): string {
  const tx = value(rule, "priority_tx");
  const rx = value(rule, "priority_rx");
  const priority = tx && rx && tx !== rx ? `${tx} tx, ${rx} rx` : (tx ?? rx);
  const capTx = value(rule, "bandwidth_cap_pct_tx");
  const capRx = value(rule, "bandwidth_cap_pct_rx");
  return joined([
    value(rule, "qos_class"),
    priority && `priority ${priority}`,
    capTx && `cap ${capTx}% tx`,
    capRx && `cap ${capRx}% rx`,
  ]);
}

/** The route actions of the rule, one line for each target that has one.
 *  When `route_type` names a target, only that target applies. */
export function routeLines(rule: SdwanPolicyRule): Array<{ target: string; text: string }> {
  const routeType = value(rule, "route_type")?.toLowerCase() ?? null;
  const lines: Array<{ target: string; text: string }> = [];
  for (const [prefix, label] of ROUTE_TARGETS) {
    if (routeType && routeType !== prefix) continue;
    const hubs = value(rule, `${prefix}_backhaul_hubs`);
    const text = joined([
      value(rule, `${prefix}_route_policy`),
      value(rule, `${prefix}_link_policy`) && `link ${value(rule, `${prefix}_link_policy`)}`,
      value(rule, `${prefix}_wanlink`) && `on ${value(rule, `${prefix}_wanlink`)}`,
      value(rule, `${prefix}_outer_dscp`) && `outer dscp ${value(rule, `${prefix}_outer_dscp`)}`,
      hubs && `backhaul via ${hubs}`,
    ]);
    if (text) lines.push({ target: label, text });
  }
  return lines;
}

/** The SLA thresholds and the NAT, in one cell. */
export function slaCell(rule: SdwanPolicyRule): string {
  return joined([
    value(rule, "sla_latency_ms") && `latency ${value(rule, "sla_latency_ms")} ms`,
    value(rule, "sla_jitter_ms") && `jitter ${value(rule, "sla_jitter_ms")} ms`,
    value(rule, "sla_loss_pct") && `loss ${value(rule, "sla_loss_pct")}%`,
    value(rule, "nat_source") && `source NAT ${value(rule, "nat_source")}`,
    value(rule, "nat_dest") && `destination NAT ${value(rule, "nat_dest")}`,
  ]);
}

/** The rules grouped by segment, in the order the edge reads them. */
export function bySegment(rules: SdwanPolicyRule[]): Array<{ segment: string; rules: SdwanPolicyRule[] }> {
  const groups = new Map<string, SdwanPolicyRule[]>();
  for (const r of rules) {
    const key = String(r.segment_name ?? r.segment_id ?? "");
    groups.set(key, [...(groups.get(key) ?? []), r]);
  }
  return [...groups].map(([segment, list]) => ({
    segment,
    rules: [...list].sort((a, b) => a.position - b.position),
  }));
}

/** The gap is JSON with an `operation` field. */
export function gapSentence(gap: string): string {
  let operation: string | null = null;
  try {
    const parsed: unknown = JSON.parse(gap);
    if (parsed !== null && typeof parsed === "object" && "operation" in parsed) {
      const op = (parsed as { operation: unknown }).operation;
      if (typeof op === "string" && op) operation = op.split("/").pop() || op;
    }
  } catch {
    // a gap that is not JSON names no operation
  }
  return operation ? `No QOS profile body from ${operation}` : "No QOS profile body";
}
