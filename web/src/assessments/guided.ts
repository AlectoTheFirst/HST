import type { AnalysisKind, Requirement } from "./types";

export type ObjectKind = "device" | "interface" | "rulebase" | "link" | "tunnel" | "domain";
/** The kinds of the context of a Business Application connection end. */
export type ContextKind = "identity" | "segment";
interface NamedObject {
  uid: string;
  name: string;
}
export interface DiscoveryObject extends NamedObject {
  kind: ObjectKind | ContextKind | "service" | "ip" | "network";
  device?: NamedObject;
  devices?: NamedObject[];
  device_uid?: string;
  device_name?: string;
  site?: string;
  context?: NamedObject;
  addresses?: string[];
  interfaces?: string[];
  members?: (NamedObject & { kind: ObjectKind })[];
  source?: string;
  evidence_status?: "declared" | "observed" | "unknown";
  valid_from_ms?: number | null;
  valid_until_ms?: number | null;
  evidence_refs?: string[];
  selectable: boolean;
  disabled_reason?: string;
  suggested?: boolean;
  suggestion_reason?: string;
  definition?: Requirement;
  origin?: "graph" | "saved";
  requirement_id?: string;
  requirement_revision?: number;
  origin_requirement?: string;
  origin_snapshot?: string;
  locations?: string[];
  applications?: string[];
  match_reasons?: string[];
}
export interface DiscoveryResponse {
  snapshot: string;
  items: DiscoveryObject[];
  truncated: boolean;
  scope?: string;
  facets?: { locations: string[]; applications: string[] };
  questions?: string[];
  catalog_complete?: boolean;
  saved_catalog_complete?: boolean;
  traffic_options?: TrafficOption[];
}
export interface ServiceSelection {
  uid: string;
  name: string;
  request: Requirement;
  /** Exact request, also exposed under the discovery API's name. */
  definition: Requirement;
  origin: "graph" | "saved";
  requirementId?: string;
  requirementRevision?: number;
  originRequirement?: string;
  originSnapshot?: string;
}
export const analysisQuestions: Record<AnalysisKind, string> = {
  evaluate: "Check this service",
  troubleshoot: "Troubleshoot this service",
  regression: "Explain what changed",
  repair: "Find a safe repair",
  resilience: "Test service resilience",
  verify: "Verify a deployment",
};
export function objectDescription(item: DiscoveryObject): string {
  return [item.device?.name ?? item.device_name, item.site, item.context?.name, item.source]
    .filter(Boolean)
    .join(", ");
}
export function optionsPath(
  snapshot: string,
  kind: string,
  query = "",
  assessmentId?: string,
  uid?: string,
): string {
  const params = new URLSearchParams({ snapshot, kind });
  if (query) params.set("q", query);
  if (assessmentId) params.set("assessment_id", assessmentId);
  if (uid) params.set("uid", uid);
  return `/assessment-options?${params.toString()}`;
}
export interface RepairScope {
  source: string[];
  destination: string[];
  protocols: string[];
  ports: string[];
  source_ports: string[];
}
/** A dimension that a member leaves unspecified stays empty. */
export function scopeFromRequest(request?: Requirement): RepairScope {
  const unique = (values: string[]) => [...new Set(values)];
  const dimensions = (key: "proto" | "port" | "source_port") =>
    request?.members.some((member) => !(member[key] ?? request[key]))
      ? []
      : unique(
          request?.members
            .map((member) => member[key] ?? request[key])
            .filter((v): v is string => !!v) ?? [],
        );
  return {
    source: request?.sources ?? [],
    destination: unique(request?.members.flatMap((member) => member.addresses) ?? []),
    protocols: dimensions("proto"),
    ports: dimensions("port"),
    source_ports: dimensions("source_port"),
  };
}

export interface ServiceClues {
  destination: string;
  client: string;
  location: string;
  application: string;
}
export const emptyServiceClues = (): ServiceClues => ({
  destination: "",
  client: "",
  location: "",
  application: "",
});
export function serviceClues(value: unknown): ServiceClues {
  const input = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  return {
    destination: typeof input.destination === "string" ? input.destination : "",
    client: typeof input.client === "string" ? input.client : "",
    location: typeof input.location === "string" ? input.location : "",
    application: typeof input.application === "string" ? input.application : "",
  };
}
export function literalAddress(value: string): boolean {
  const [address, prefix, extra] = value.trim().split("/");
  if (!address || extra !== undefined) return false;
  let bits = 32;
  if (address.includes(":")) {
    try {
      if (!new URL(`http://[${address}]/`).hostname.startsWith("[")) return false;
    } catch {
      return false;
    }
    bits = 128;
  } else if (
    address.split(".").length !== 4 ||
    address.split(".").some((part) => !/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255)
  )
    return false;
  return prefix === undefined || (/^(0|[1-9]\d{0,2})$/.test(prefix) && Number(prefix) <= bits);
}
export function destinationClue(value: string): { address: string; label: string; port: string } {
  const input = value.trim();
  if (literalAddress(input)) return { address: input, label: input, port: "" };
  try {
    const url = new URL(input.includes("://") ? input : `http://${input}`);
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const authority =
      input
        .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
        .split(/[/?#]/)[0]
        .split("@")
        .at(-1) || "";
    const explicitPort = authority.match(/:(\d+)$/)?.[1] || "";
    return {
      address: literalAddress(host) ? host : "",
      label: host,
      port: explicitPort || url.port,
    };
  } catch {
    return { address: "", label: input, port: "" };
  }
}

export interface TrafficOption extends NamedObject {
  role: "client" | "destination";
  addresses: string[];
  site?: string;
  device?: NamedObject;
  context?: NamedObject;
  match_reasons?: string[];
  selectable?: boolean;
  disabled_reason?: string;
}
export interface TrafficEndpoints {
  client?: TrafficOption;
  destination?: TrafficOption;
}
