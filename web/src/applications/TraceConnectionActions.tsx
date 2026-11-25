import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { AssessmentDraft, Requirement } from "../assessments/types";
import type {
  AnalysisSessionRecord,
  ConnectionAnalysisInput,
  SnapshotReference,
} from "../analysis/contracts";
import type {
  ApplicationRevision,
  BusinessApplicationDefinition,
  DestinationCondition,
} from "./types";

const slug = (value: string) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48);
export const catalogId = (value: string, fallback = "trace-connection") => {
  const candidate = slug(value) || fallback;
  return /^[a-z]/.test(candidate) ? candidate : `connection-${candidate}`.slice(0, 63);
};

function portList(value?: string | null): Array<number | string> | null {
  if (!value) return null;
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => (/^\d+$/.test(part) ? Number(part) : part));
}

export function TraceConnectionActions({
  draft,
  onOpenAnalysis,
  onOpenApplication,
}: {
  draft: AssessmentDraft;
  onOpenAnalysis: (id: string) => void;
  onOpenApplication: (id: string) => void;
}) {
  const request = draft.definition.request!;
  const [open, setOpen] = useState(false);
  const [applicationId, setApplicationId] = useState("");
  const [serviceId, setServiceId] = useState("");
  const [idText, setIdText] = useState(() =>
    catalogId(request.name || `${request.sources[0]}-${request.destination}`),
  );
  const connectionId = catalogId(idText);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();
  const catalog = useQuery({
    queryKey: ["business-applications"],
    queryFn: () => api<{ applications: ApplicationRevision[] }>("/business-applications"),
    enabled: open,
  });
  const selected = catalog.data?.applications.find((item) => item.id === applicationId);

  async function saveDraft() {
    setBusy(true);
    setError("");
    try {
      const snapshot = await api<SnapshotReference>(
        `/analysis-snapshot?snapshot=${encodeURIComponent(draft.definition.snapshot)}`,
      );
      const input: ConnectionAnalysisInput = {
        kind: "connection",
        snapshot,
        connections: [
          { id: connectionId, name: request.name, source: { kind: "inline", request } },
        ],
        changes: [],
        mode: "possible",
      };
      const record = await api<AnalysisSessionRecord>("/analysis-sessions", {
        method: "POST",
        body: { title: `${request.name} connection draft`, input },
      });
      void queryClient.invalidateQueries({ queryKey: ["analysis-sessions"] });
      onOpenAnalysis(record.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not save the connection draft");
    } finally {
      setBusy(false);
    }
  }

  async function addToService() {
    if (!selected || !serviceId) return;
    setBusy(true);
    setError("");
    try {
      const full = await api<{ application: ApplicationRevision }>(
        `/business-applications/${encodeURIComponent(selected.id)}`,
      );
      const record = full.application;
      const definition: BusinessApplicationDefinition = structuredClone(record.definition);
      if (definition.connections.some((item) => item.id === connectionId))
        throw new Error("Connection ID already exists in the selected application");
      if (request.members.some((member) => member.addresses.length !== 1))
        throw new Error("Destination member with multiple addresses");
      if (
        request.members.some(
          (member) =>
            (member.proto && member.proto !== request.proto) ||
            (member.port && member.port !== request.port) ||
            (member.source_port && member.source_port !== request.source_port),
        )
      )
        throw new Error("Per-destination traffic overrides");
      const sourceGroupId = `${connectionId}-source`.slice(0, 63);
      const destinationGroupId = `${connectionId}-destination`.slice(0, 63);
      if (
        definition.groups.some(
          (group) => group.id === sourceGroupId || group.id === destinationGroupId,
        )
      )
        throw new Error("Endpoint group IDs already exist");
      definition.groups.push({
        id: sourceGroupId,
        name: `${request.name} sources`,
        members: request.sources.map((address, index) => ({ id: `source-${index + 1}`, address })),
      });
      definition.groups.push({
        id: destinationGroupId,
        name: request.destination,
        members: request.members.map((member, index) => ({
          id: catalogId(member.name, `destination-${index + 1}`),
          name: member.name,
          address: member.addresses[0],
        })),
      });
      const memberMap = new Map(
        request.members.map((member, index) => [
          member.name,
          catalogId(member.name, `destination-${index + 1}`),
        ]),
      );
      const condition = mapCondition(request, memberMap);
      const sourceContext = {
        vrf: request.source_context ?? null,
        device_uid: request.source_device_uid ?? null,
        identity_uid: request.identity_uid ?? null,
        segment_uid: request.segment_uid ?? null,
      };
      definition.connections.push({
        id: connectionId,
        name: request.name,
        source: sourceGroupId,
        destination: destinationGroupId,
        protocol: request.proto,
        destination_ports: portList(request.port),
        source_ports: portList(request.source_port),
        success: request.success as "forward" | "round-trip" | "session",
        destination_condition: condition,
        source_context: Object.values(sourceContext).some(Boolean) ? sourceContext : null,
        mtu: request.mtu ? { ...request.mtu } : null,
        provenance: {
          trace_id: `trace:${connectionId}`,
          snapshot: draft.definition.snapshot,
          captured_fields: [
            "source",
            "destination",
            "protocol",
            "destination_ports",
            "source_ports",
            "source_context",
            "source_device_uid",
            "identity_uid",
            "segment_uid",
            "mtu",
          ],
        },
        header_constraints: {},
      });
      const service = definition.services.find((item) => item.id === serviceId);
      if (!service) throw new Error("No service chosen");
      service.connection_ids.push(connectionId);
      await api(`/business-applications/${encodeURIComponent(record.id)}`, {
        method: "PUT",
        body: { definition, expected_revision: record.revision, source: "trace" },
      });
      void queryClient.invalidateQueries({ queryKey: ["business-applications"] });
      void queryClient.invalidateQueries({ queryKey: ["business-application", record.id] });
      onOpenApplication(record.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not add the connection");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="trace-connection-actions">
      <button type="button" className="secondary" onClick={() => setOpen(!open)}>
        Save connection
      </button>
      {open && (
        <div className="trace-connection-popover" role="dialog" aria-label="Save trace connection">
          <label>
            Connection ID
            <input value={idText} onChange={(event) => setIdText(event.target.value)} />
          </label>
          <button type="button" disabled={busy || !idText.trim()} onClick={() => void saveDraft()}>
            Save connection draft
          </button>
          <hr />
          <label>
            Business application
            <select
              value={applicationId}
              onChange={(event) => {
                setApplicationId(event.target.value);
                setServiceId("");
              }}
            >
              <option value="">Choose application</option>
              {catalog.data?.applications.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          {catalog.isError && <p role="alert">Applications not loaded</p>}
          <label>
            Service
            <select
              value={serviceId}
              disabled={!selected}
              onChange={(event) => setServiceId(event.target.value)}
            >
              <option value="">Choose service</option>
              {selected?.definition.services.map((service) => (
                <option key={service.id} value={service.id}>
                  {service.name}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            disabled={busy || !selected || !serviceId || !idText.trim()}
            onClick={() => void addToService()}
          >
            Add connection to service
          </button>
          {error && <p role="alert">{error}</p>}
        </div>
      )}
    </div>
  );
}

function mapCondition(request: Requirement, names: Map<string, string>) {
  const walk = (condition: Requirement["condition"]): DestinationCondition =>
    condition.kind === "member"
      ? { kind: "member", member: names.get(condition.member ?? "") ?? "", parts: [] }
      : { kind: condition.kind, n: condition.n, parts: (condition.parts ?? []).map(walk) };
  return walk(request.condition);
}
