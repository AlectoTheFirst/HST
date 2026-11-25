import type { MtuRequest } from "../api/types";
import { readJson } from "../shell/storage";
import "./mtu.css";

export const MTU_QUERY_KEY = "hst.trace.mtu";
const modes = ["off", "inventory", "unfragmented", "packet"] as const;

export function initialMtuRequest(): MtuRequest {
  const saved = readJson<unknown>(MTU_QUERY_KEY, null);
  if (!saved || typeof saved !== "object" || !("mode" in saved) || !modes.includes(saved.mode as typeof modes[number])) return { mode: "inventory" };
  const value = saved as Record<string, unknown>;
  const request: MtuRequest = { mode: value.mode as MtuRequest["mode"] };
  for (const key of ["ip_packet_bytes", "reply_ip_packet_bytes"] as const) {
    if (typeof value[key] === "number" && Number.isInteger(value[key]) && value[key] >= 20 && value[key] <= 65575) request[key] = value[key];
  }
  if (typeof value.ipv4_df === "boolean") request.ipv4_df = value.ipv4_df;
  if (typeof value.traffic_class === "string") request.traffic_class = value.traffic_class.slice(0, 256);
  return request;
}

/** The request holds only the fields of the controls that are shown. */
export function submittedMtuRequest(value: MtuRequest, ipv6: boolean, replyEnabled: boolean): MtuRequest {
  const mode = value.mode ?? "inventory";
  if (mode === "off") return { mode };
  const request: MtuRequest = { mode, ...(value.traffic_class?.trim() ? { traffic_class: value.traffic_class.trim() } : {}) };
  if (mode === "packet" || mode === "unfragmented") {
    request.ip_packet_bytes = value.ip_packet_bytes;
    if (replyEnabled && value.reply_ip_packet_bytes != null) request.reply_ip_packet_bytes = value.reply_ip_packet_bytes;
    if (mode === "packet" && !ipv6 && value.ipv4_df != null) request.ipv4_df = value.ipv4_df;
  }
  return request;
}

export function MtuControls({ value, onChange, ipv6 = false, replyEnabled = false }: {
  value: MtuRequest;
  onChange: (value: MtuRequest) => void;
  ipv6?: boolean;
  replyEnabled?: boolean;
}) {
  const mode = value.mode ?? "inventory";
  const sized = mode === "unfragmented" || mode === "packet";
  return <fieldset className="mtu-controls">
    <legend>MTU</legend>
    <label>Assessment<select value={mode} onChange={(e) => onChange({ ...value, mode: e.target.value as MtuRequest["mode"] })}>
      <option value="off">Off</option><option value="inventory">Inspect evidence</option>
      <option value="unfragmented">Unfragmented size</option><option value="packet">Packet behavior</option>
    </select></label>
    {sized && <>
      <label>IP packet bytes<input type="number" min={ipv6 ? 40 : 20} max={ipv6 ? 65575 : 65535} step="1" required value={value.ip_packet_bytes ?? ""} onChange={(e) => onChange({ ...value, ip_packet_bytes: e.target.value === "" ? undefined : Number(e.target.value) })} /></label>
      {mode === "packet" && !ipv6 && <label>IPv4 Don't Fragment<select value={value.ipv4_df === true ? "true" : value.ipv4_df === false ? "false" : "unknown"} onChange={(e) => onChange({ ...value, ipv4_df: e.target.value === "unknown" ? undefined : e.target.value === "true" })}>
        <option value="unknown">Not stated</option><option value="true">Set</option><option value="false">Clear</option>
      </select></label>}
      {replyEnabled && <label>Reply IP packet bytes<input type="number" min={ipv6 ? 40 : 20} max={ipv6 ? 65575 : 65535} step="1" value={value.reply_ip_packet_bytes ?? ""} onChange={(e) => onChange({ ...value, reply_ip_packet_bytes: e.target.value === "" ? undefined : Number(e.target.value) })} placeholder="Not stated" /></label>}
    </>}
    {mode !== "off" && <label>Traffic class<input value={value.traffic_class ?? ""} maxLength={256} onChange={(e) => onChange({ ...value, traffic_class: e.target.value })} placeholder="Not stated" /></label>}
  </fieldset>;
}
