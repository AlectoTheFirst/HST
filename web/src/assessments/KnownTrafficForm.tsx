import type { MtuRequest } from "../api/types";
import { MtuRequirementFields } from "./MtuRequirementFields";
import { requirementError } from "./types";
import { useState } from "react";
import { Field } from "./RequirementComposer";
import { destinationClue, literalAddress } from "./guided";
import type { ServiceClues, TrafficEndpoints } from "./guided";
import type { Requirement } from "./types";

export function KnownTrafficForm({
  clues,
  endpoints = {},
  onApply,
  onCancel,
}: {
  clues: ServiceClues;
  endpoints?: TrafficEndpoints;
  onApply: (request: Requirement) => void;
  onCancel: () => void;
}) {
  const destination = destinationClue(clues.destination);
  const clients = clues.client.split(/[\s,]+/).filter(Boolean);
  const [name, setName] = useState(
    clues.application || (destination.label ? `Traffic to ${destination.label}` : ""),
  );
  const [selectedSource, setSelectedSource] = useState(endpoints.client);
  const [source, setSource] = useState(
    endpoints.client?.addresses.join(", ") ||
      (clients.length && clients.every(literalAddress) ? clients.join(", ") : ""),
  );
  const [address, setAddress] = useState(
    endpoints.destination?.addresses.join(", ") || destination.address,
  );
  const [proto, setProto] = useState("");
  const [port, setPort] = useState(destination.port);
  const [success, setSuccess] = useState("");
  const [mtu, setMtu] = useState<MtuRequest | undefined>();
  const [error, setError] = useState("");
  function apply() {
    const sources = source.split(/[\s,]+/).filter(Boolean);
    const addresses = address.split(/[\s,]+/).filter(Boolean);
    if (
      !name.trim() ||
      !sources.length ||
      !addresses.length ||
      !sources.every(literalAddress) ||
      !addresses.every(literalAddress)
    ) {
      setError("Traffic label and valid client and destination IP addresses or subnets required");
      return;
    }
    if (
      !proto ||
      !success ||
      (["tcp", "udp"].includes(proto) && (!/^\d+$/.test(port) || Number(port) > 65535))
    ) {
      setError(
        "Protocol, connectivity and, for TCP or UDP, a destination port from 0 to 65535 required",
      );
      return;
    }
    const request: Requirement = {
      ...(mtu ? { mtu } : {}),
      name: name.trim(),
      destination: destination.label || name.trim(),
      sources,
      members: [
        {
          name: "destination",
          addresses,
          proto,
          port: ["tcp", "udp"].includes(proto) ? port : null,
        },
      ],
      condition: { kind: "member", member: "destination" },
      success,
      ...(selectedSource?.context ? { source_context: selectedSource.context.uid } : {}),
    };
    const invalid = requirementError(request);
    if (invalid) {
      setError(invalid);
      return;
    }
    onApply(request);
  }
  return (
    <fieldset className="assessment-known-traffic">
      <legend>Known traffic</legend>
      {(clues.destination || clues.location || clues.client || clues.application) && (
        <p>
          Starting clues:{" "}
          {[clues.application, clues.destination, clues.client, clues.location]
            .filter(Boolean)
            .join(", ")}
        </p>
      )}
      {selectedSource && (
        <p>
          Selected client:{" "}
          {[
            selectedSource.name,
            selectedSource.site,
            selectedSource.device?.name,
            selectedSource.context?.name,
          ]
            .filter(Boolean)
            .join(", ")}
        </p>
      )}
      <div className="assessment-fields">
        <Field label="Application or traffic label" value={name} onChange={setName} />
        <Field
          label="Client IP addresses or subnets"
          value={source}
          onChange={(value) => {
            setSource(value);
            setSelectedSource(undefined);
          }}
        />
        <Field label="Destination IP addresses or subnets" value={address} onChange={setAddress} />
        <label className="assessment-field">
          <span>Traffic protocol</span>
          <select value={proto} onChange={(event) => setProto(event.target.value)}>
            <option value="">Choose the known protocol</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
            <option value="icmpv6">ICMPv6</option>
          </select>
        </label>
        {!["icmp", "icmpv6"].includes(proto) && (
          <Field label="Traffic destination port" type="number" value={port} onChange={setPort} />
        )}
        <label className="assessment-field">
          <span>Connectivity to check</span>
          <select value={success} onChange={(event) => setSuccess(event.target.value)}>
            <option value="">Choose the required behavior</option>
            <option value="forward">Forward connectivity</option>
            <option value="round-trip">Round trip</option>
            <option value="session">Session connectivity</option>
          </select>
        </label>
      </div>
      <MtuRequirementFields value={mtu} onChange={setMtu} ipv6={source.includes(":")} />
      {error && <p role="alert">{error}</p>}
      <div className="assessment-actions">
        <button type="button" onClick={apply}>
          Use this traffic definition
        </button>
        <button type="button" onClick={onCancel}>
          Cancel traffic definition
        </button>
      </div>
    </fieldset>
  );
}
