/** GATE_KINDS holds the kinds with `gate=True` in `src/hst/core/labels.py`, without `NatRule`. */

export const GATE_KINDS: ReadonlySet<string> = new Set([
  "RoutePolicy",
  "SdwanBusinessPolicy",
  "Contract",
  "VzAny",
  "PbrPolicy",
  "FwRulebase",
  "VirtualService",
  "ZpaAccessRule",
  "ZpaClientForwardingRule",
  "ZiaForwardingRule",
  "NatGw",
  "AzFirewall",
  "ForwardingBoundary",
]);

/** GATE_KINDS applies to a stored response without the `gate` flag. */
export function isGate(hop: { kind: string; gate?: boolean }): boolean {
  return hop.gate ?? GATE_KINDS.has(hop.kind);
}
