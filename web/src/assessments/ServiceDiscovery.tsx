import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { conditionSentence } from "./types";
import { emptyServiceClues, objectDescription, optionsPath } from "./guided";
import type {
  DiscoveryObject,
  DiscoveryResponse,
  ServiceClues,
  ServiceSelection,
  TrafficEndpoints,
  TrafficOption,
} from "./guided";

export function ServiceDiscovery({
  snapshot,
  onSelect,
  onDefineTraffic,
  initialClues,
  onCluesChange,
}: {
  snapshot: string;
  onSelect: (item: ServiceSelection) => void;
  initialClues?: ServiceClues;
  onDefineTraffic?: (clues: ServiceClues, endpoints?: TrafficEndpoints) => void;
  onCluesChange?: (clues: ServiceClues) => void;
}) {
  const [clues, setClues] = useState(initialClues ?? emptyServiceClues());
  const [applied, setApplied] = useState(initialClues ?? emptyServiceClues());
  const [endpoints, setEndpoints] = useState<TrafficEndpoints>({});
  const [groupBy, setGroupBy] = useState<"locations" | "applications">("locations");
  const id = useId();
  const dirty = JSON.stringify(clues) !== JSON.stringify(applied);
  const query = useQuery({
    queryKey: ["assessment-service-clues", snapshot, applied],
    queryFn: () => {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(applied))
        if (value.trim()) params.set(key, value.trim());
      return api<DiscoveryResponse>(
        `${optionsPath(snapshot, "service")}${params.size ? `&${params.toString()}` : ""}`,
      );
    },
    enabled: !!snapshot,
  });
  const all = query.data?.items.filter((item) => item.kind === "service") ?? [];
  const groups = new Map<string, DiscoveryObject[]>();
  for (const item of all) {
    const names = item[groupBy]?.length
      ? item[groupBy]!
      : [groupBy === "locations" ? "Location not recorded" : "Application not recorded"];
    for (const name of names) groups.set(name, [...(groups.get(name) ?? []), item]);
  }
  function field(key: keyof ServiceClues, value: string) {
    const next = { ...clues, [key]: value };
    setClues(next);
    setEndpoints({});
    onCluesChange?.(next);
  }
  function choose(item: DiscoveryObject) {
    if (!item.selectable || !item.definition || dirty) return;
    onSelect({
      uid: item.uid,
      name: item.name,
      request: item.definition,
      definition: item.definition,
      origin: item.origin || "graph",
      requirementId: item.requirement_id,
      requirementRevision: item.requirement_revision,
      originRequirement: item.origin_requirement,
      originSnapshot: item.origin_snapshot,
    });
  }
  const questions = query.data?.questions ?? [];
  function traffic(item: TrafficOption) {
    setEndpoints({ ...endpoints, [item.role]: item });
  }
  const trafficOptions = query.data?.traffic_options ?? [];
  return (
    <section className="assessment-service-discovery" aria-label="Service discovery">
      <h3>Service clues</h3>
      <div className="assessment-fields">
        <label className="assessment-field">
          <span>Destination URL, hostname or IP</span>
          <input
            value={clues.destination}
            maxLength={500}
            placeholder="https://pay.example.test or 192.0.2.10"
            onChange={(event) => field("destination", event.target.value)}
          />
        </label>
        <label className="assessment-field">
          <span>Client IP or subnet</span>
          <input
            value={clues.client}
            maxLength={200}
            placeholder="10.20.0.0/24"
            onChange={(event) => field("client", event.target.value)}
          />
        </label>
        <label className="assessment-field">
          <span>Client location</span>
          <input
            value={clues.location}
            maxLength={200}
            list={`${id}-locations`}
            placeholder="Site, device or VPN name"
            onChange={(event) => field("location", event.target.value)}
          />
          <datalist id={`${id}-locations`}>
            {(query.data?.facets?.locations ?? []).map((value) => (
              <option key={value} value={value} />
            ))}
          </datalist>
        </label>
        <label className="assessment-field">
          <span>Application</span>
          <input
            value={clues.application}
            maxLength={200}
            list={`${id}-applications`}
            placeholder="payments or email"
            onChange={(event) => field("application", event.target.value)}
          />
          <datalist id={`${id}-applications`}>
            {(query.data?.facets?.applications ?? []).map((value) => (
              <option key={value} value={value} />
            ))}
          </datalist>
        </label>
      </div>
      <button type="button" disabled={!snapshot} onClick={() => setApplied({ ...clues })}>
        Find matching services
      </button>
      {dirty && <p role="status">Clues changed</p>}
      {query.isPending && <p role="status">Finding recorded services</p>}
      {query.isError && (
        <p role="alert">
          Could not search the recorded services{" "}
          <button type="button" onClick={() => void query.refetch()}>
            Retry matching
          </button>
        </p>
      )}
      {!!questions.length && (
        <div className="assessment-service-clues">
          <h4>Questions</h4>
          <ul>
            {questions.map((question, index) => (
              <li key={index}>{question}</li>
            ))}
          </ul>
        </div>
      )}
      {!query.isPending && !query.isError && !all.length && (
        <p role="status">No matching service</p>
      )}
      {!!all.length && (
        <>
          <label className="assessment-field">
            <span>Grouping</span>
            <select
              value={groupBy}
              onChange={(event) => setGroupBy(event.target.value as typeof groupBy)}
            >
              <option value="locations">Location</option>
              <option value="applications">Application</option>
            </select>
          </label>
          <div className="assessment-service-groups">
            {[...groups].map(([name, items]) => (
              <section
                key={name}
                aria-label={`${groupBy === "locations" ? "Location" : "Application"}: ${name}`}
              >
                <h4>{name}</h4>
                <ul className="assessment-picker-results">
                  {items.map((item) => (
                    <li key={`${item.origin || "graph"}:${item.uid}`}>
                      <button
                        type="button"
                        disabled={dirty || !item.selectable || !item.definition}
                        aria-label={`Choose ${item.name} in ${name}`}
                        onClick={() => choose(item)}
                      >
                        <strong>{item.name}</strong>
                        <span>{objectDescription(item)}</span>
                        <span>
                          {item.origin === "saved" ? "Saved service" : "Recorded service"}
                        </span>
                      </button>
                      {!!item.match_reasons?.length && (
                        <p>Matches: {item.match_reasons.join(", ")}</p>
                      )}
                      {item.definition && (
                        <>
                          <p>Clients: {item.definition.sources.join(", ")}</p>
                          <p>Destination: {item.definition.destination}</p>
                          <ul>
                            {item.definition.members.map((member) => (
                              <li key={member.name}>
                                {member.name}: {member.addresses.join(", ")} /{" "}
                                {member.proto ?? item.definition!.proto ?? "protocol unspecified"} /
                                port {member.port ?? item.definition!.port ?? "unspecified"}
                                {(member.source_port ?? item.definition!.source_port)
                                  ? ` / source port ${member.source_port ?? item.definition!.source_port}`
                                  : ""}
                              </li>
                            ))}
                          </ul>
                          <p>
                            {conditionSentence(item.definition.condition)},{" "}
                            {item.definition.success} connectivity
                          </p>
                        </>
                      )}
                      {(!item.selectable || !item.definition) && (
                        <p>{item.disabled_reason || "Recorded service incomplete"}</p>
                      )}
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </div>
        </>
      )}
      {(query.data?.truncated ||
        query.data?.catalog_complete === false ||
        query.data?.saved_catalog_complete === false) && (
        <p role="status">Catalog search incomplete</p>
      )}
      {onDefineTraffic && !!trafficOptions.length && (
        <section aria-label="Recorded traffic addresses">
          <h4>Recorded traffic addresses</h4>
          <ul className="assessment-picker-results">
            {trafficOptions.map((item) => (
              <li key={`${item.role}:${item.uid}`}>
                <button
                  type="button"
                  disabled={dirty || item.selectable === false}
                  aria-pressed={endpoints[item.role]?.uid === item.uid}
                  onClick={() => traffic(item)}
                >
                  <strong>
                    {item.role === "client" ? "Client" : "Destination"}: {item.name}
                  </strong>
                  <span>{item.addresses.join(", ")}</span>
                  <span>
                    {[item.site, item.device?.name, item.context?.name].filter(Boolean).join(", ")}
                  </span>
                </button>
                {!!item.match_reasons?.length && <p>{item.match_reasons.join(", ")}</p>}
                {item.selectable === false && (
                  <p>{item.disabled_reason || "Ambiguous address scope"}</p>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
      {onDefineTraffic && (
        <button type="button" onClick={() => onDefineTraffic(clues, endpoints)}>
          Define traffic from these clues
        </button>
      )}
    </section>
  );
}
