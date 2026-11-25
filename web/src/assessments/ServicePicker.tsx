import { useEffect, useId, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { SavedRequirement } from "./types";
import { conditionSentence, requirementError } from "./types";
import { objectDescription, optionsPath } from "./guided";
import { ServiceDiscovery } from "./ServiceDiscovery";
import type { DiscoveryResponse, ServiceSelection, ServiceClues, TrafficEndpoints } from "./guided";

interface ServicePickerProps {
  snapshot: string;
  label?: string;
  onSelect: (item: ServiceSelection) => void;
  onDefineTraffic?: (clues: ServiceClues, endpoints?: TrafficEndpoints) => void;
  initialClues?: ServiceClues;
  onCluesChange?: (clues: ServiceClues) => void;
}
export function ServicePicker(props: ServicePickerProps) {
  return <ServiceSearch key={props.snapshot} {...props} />;
}
function ServiceSearch({
  snapshot,
  label = "Find a service",
  onSelect,
  onDefineTraffic,
  initialClues,
  onCluesChange,
}: ServicePickerProps) {
  const [query, setQuery] = useState("");
  const [unknownName, setUnknownName] = useState(
    !!initialClues && Object.values(initialClues).some(Boolean),
  );
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  const id = useId();
  const [resolving, setResolving] = useState<string | null>(null);
  const [resolutionError, setResolutionError] = useState("");
  const graph = useQuery({
    queryKey: ["assessment-options", snapshot, "service", query],
    queryFn: () => api<DiscoveryResponse>(optionsPath(snapshot, "service", query)),
    enabled: !!snapshot && !unknownName,
  });
  const saved = useQuery({
    queryKey: ["requirements"],
    queryFn: () => api<{ requirements: SavedRequirement[] }>("/requirements"),
  });
  const items: (ServiceSelection & { detail: string })[] = [
    ...(saved.data?.requirements ?? [])
      .filter(
        (item) =>
          item.definition.request &&
          `${item.title} ${item.definition.request.name}`
            .toLowerCase()
            .includes(query.toLowerCase()),
      )
      .map((item) => ({
        uid: item.id,
        name: item.title,
        request: item.definition.request!,
        definition: item.definition.request!,
        origin: "saved" as const,
        requirementId: item.id,
        requirementRevision: item.revision,
        originRequirement: item.definition.origin_requirement || undefined,
        originSnapshot: item.definition.origin_snapshot || undefined,
        detail: `Saved service, revision ${item.revision}`,
      })),
    ...(graph.data?.items ?? [])
      .filter(
        (item) =>
          item.kind === "service" && item.origin !== "saved" && item.selectable && item.definition,
      )
      .map((item) => ({
        uid: item.uid,
        name: item.name,
        request: item.definition!,
        definition: item.definition!,
        origin: "graph" as const,
        detail: ["Recorded service", objectDescription(item)].filter(Boolean).join(", "),
      })),
  ];
  async function selectSavedReference(item: SavedRequirement) {
    setResolving(item.id);
    setResolutionError("");
    try {
      const response = await api<DiscoveryResponse>(
        optionsPath(snapshot, "service", "", undefined, item.definition.requirement),
      );
      const resolved = response.items.find((entry) => entry.uid === item.definition.requirement);
      if (!resolved?.selectable || !resolved.definition)
        throw new Error(resolved?.disabled_reason || "Saved service not resolved at this snapshot");
      if (!active.current) return;
      onSelect({
        uid: item.id,
        name: item.title,
        request: resolved.definition,
        definition: resolved.definition,
        origin: "saved",
        originRequirement: item.definition.requirement,
        originSnapshot: snapshot,
      });
    } catch (cause) {
      if (active.current)
        setResolutionError(
          cause instanceof Error ? cause.message : "Could not resolve the saved service",
        );
    } finally {
      if (active.current) setResolving(null);
    }
  }
  const savedReferences = (saved.data?.requirements ?? []).filter(
    (item) =>
      !item.definition.request &&
      item.definition.requirement &&
      item.title.toLowerCase().includes(query.toLowerCase()),
  );
  const unavailable = (graph.data?.items ?? []).filter(
    (item) => item.kind === "service" && (!item.selectable || !item.definition),
  );
  return (
    <div className="assessment-picker">
      <div className="assessment-actions">
        <button
          type="button"
          aria-pressed={unknownName}
          disabled={!!resolving}
          onClick={() => setUnknownName(!unknownName)}
        >
          {unknownName ? "Search by service name" : "Search by clues"}
        </button>
      </div>
      {unknownName ? (
        <ServiceDiscovery
          snapshot={snapshot}
          onSelect={onSelect}
          onDefineTraffic={onDefineTraffic}
          initialClues={initialClues}
          onCluesChange={onCluesChange}
        />
      ) : (
        <>
          <label className="assessment-field" htmlFor={id}>
            <span>{label}</span>
            <input
              id={id}
              type="search"
              value={query}
              disabled={!snapshot}
              placeholder="Search saved or recorded services"
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          {!snapshot ? (
            <p>No snapshot selected</p>
          ) : (
            <>
              {(graph.isPending || saved.isPending) && <p role="status">Loading services</p>}
              {(graph.isError || saved.isError) && (
                <p role="alert">
                  {graph.isError ? "Could not load recorded services " : ""}
                  {saved.isError ? "Could not load saved services " : ""}
                  <button
                    type="button"
                    onClick={() => {
                      if (graph.isError) void graph.refetch();
                      if (saved.isError) void saved.refetch();
                    }}
                  >
                    Retry service search
                  </button>
                </p>
              )}
              <ul className="assessment-picker-results" aria-label={`${label} results`}>
                {items.map((item) => (
                  <li key={`${item.origin}:${item.uid}`}>
                    <button
                      type="button"
                      aria-label={`${item.name} ${item.detail} ${item.request.sources.join(", ")} to ${item.request.destination}`}
                      disabled={!!resolving || !!requirementError(item.request)}
                      onClick={() => onSelect(item)}
                    >
                      <strong>{item.name}</strong>
                      <span> {item.detail}</span>
                      <span>
                        {" "}
                        {item.request.sources.join(", ")} to {item.request.destination}
                      </span>
                    </button>
                    <p className="assessment-note">
                      {conditionSentence(item.request.condition)}, {item.request.success}{" "}
                      connectivity
                    </p>
                    {requirementError(item.request) && <p>{requirementError(item.request)}</p>}
                  </li>
                ))}
                {savedReferences.map((item) => (
                  <li key={`saved-reference:${item.id}`}>
                    <button
                      type="button"
                      disabled={!!resolving}
                      onClick={() => void selectSavedReference(item)}
                    >
                      <strong>{item.title}</strong>
                      <span> Saved service, revision {item.revision}</span>
                    </button>
                  </li>
                ))}
                {unavailable.map((item) => (
                  <li key={`unavailable:${item.uid}`}>
                    <button type="button" disabled>
                      <strong>{item.name}</strong>
                      <span> {objectDescription(item)}</span>
                    </button>
                    <p>{item.disabled_reason || "Recorded service definition incomplete"}</p>
                  </li>
                ))}
              </ul>
              {resolving && <p role="status">Resolving the saved service</p>}
              {resolutionError && <p role="alert">{resolutionError}</p>}
              {!graph.isPending &&
                !saved.isPending &&
                !items.length &&
                !savedReferences.length &&
                !unavailable.length && <p>No matching services</p>}
              {graph.data?.truncated && <p role="status">More recorded services match</p>}
            </>
          )}
        </>
      )}
    </div>
  );
}
