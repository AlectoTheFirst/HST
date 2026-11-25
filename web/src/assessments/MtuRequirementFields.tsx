import type { MtuRequest } from "../api/types";

export function MtuRequirementFields({
  value,
  onChange,
  ipv6 = false,
}: {
  value?: MtuRequest | null;
  onChange: (value: MtuRequest | undefined) => void;
  ipv6?: boolean;
}) {
  const mode = value?.mode ?? "off";
  const sized = mode === "unfragmented" || mode === "packet";
  return (
    <fieldset>
      <legend>Packet size requirement</legend>
      <label className="assessment-field">
        <span>MTU assessment</span>
        <select
          value={mode}
          onChange={(event) => {
            const next = event.target.value as MtuRequest["mode"];
            onChange(
              next === "off"
                ? undefined
                : next === "inventory"
                  ? { mode: next }
                  : {
                      mode: next,
                      ip_packet_bytes: value?.ip_packet_bytes ?? 1500,
                      ...(value?.traffic_class ? { traffic_class: value.traffic_class } : {}),
                    },
            );
          }}
        >
          <option value="off">Off</option>
          <option value="inventory">Inspect MTU evidence</option>
          <option value="unfragmented">Require unfragmented packet size</option>
          <option value="packet">Assess packet behavior</option>
        </select>
      </label>
      {sized && (
        <div className="assessment-fields">
          <label className="assessment-field">
            <span>Complete IP packet bytes</span>
            <input
              type="number"
              min={ipv6 ? 40 : 20}
              max={ipv6 ? 65575 : 65535}
              step="1"
              required
              value={value?.ip_packet_bytes ?? ""}
              onChange={(event) =>
                onChange({
                  ...value!,
                  ip_packet_bytes:
                    event.target.value === "" ? undefined : Number(event.target.value),
                })
              }
            />
          </label>
          <label className="assessment-field">
            <span>Reply IP packet bytes</span>
            <input
              type="number"
              min={ipv6 ? 40 : 20}
              max={ipv6 ? 65575 : 65535}
              step="1"
              value={value?.reply_ip_packet_bytes ?? ""}
              onChange={(event) =>
                onChange({
                  ...value!,
                  reply_ip_packet_bytes:
                    event.target.value === "" ? undefined : Number(event.target.value),
                })
              }
            />
          </label>
          {mode === "packet" && !ipv6 && (
            <label className="assessment-field">
              <span>IPv4 Don't Fragment</span>
              <select
                value={
                  value?.ipv4_df === true ? "true" : value?.ipv4_df === false ? "false" : "unknown"
                }
                onChange={(event) =>
                  onChange({
                    ...value!,
                    ipv4_df:
                      event.target.value === "unknown" ? undefined : event.target.value === "true",
                  })
                }
              >
                <option value="unknown">Not stated</option>
                <option value="true">Set</option>
                <option value="false">Clear</option>
              </select>
            </label>
          )}
        </div>
      )}
      {mode !== "off" && (
        <label className="assessment-field">
          <span>MTU traffic class</span>
          <input
            value={value?.traffic_class ?? ""}
            onChange={(event) =>
              onChange({ ...value!, traffic_class: event.target.value || undefined })
            }
          />
        </label>
      )}
    </fieldset>
  );
}
