import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { objectDescription, optionsPath } from "./guided";
import type { ContextKind, DiscoveryObject, DiscoveryResponse, ObjectKind } from "./guided";
import "./assessments.css";

const PLURAL: Partial<Record<ObjectKind | ContextKind, string>> = {
  domain: "shared failure domains",
  identity: "identity groups",
};

export function ObjectPicker({
  snapshot,
  kind,
  label,
  onSelect,
  assessmentId,
  selectedUids = [],
  device,
}: {
  snapshot: string;
  kind: ObjectKind | ContextKind;
  label: string;
  onSelect: (item: DiscoveryObject) => void;
  assessmentId?: string;
  selectedUids?: string[];
  /** The device UID that limits an interface search. */
  device?: string;
}) {
  return (
    <ObjectSearch
      key={`${snapshot}:${kind}:${device ?? ""}`}
      snapshot={snapshot}
      kind={kind}
      label={label}
      onSelect={onSelect}
      assessmentId={assessmentId}
      selectedUids={selectedUids}
      device={device}
    />
  );
}
function ObjectSearch({
  snapshot,
  kind,
  label,
  onSelect,
  assessmentId,
  selectedUids,
  device,
}: {
  snapshot: string;
  kind: ObjectKind | ContextKind;
  label: string;
  onSelect: (item: DiscoveryObject) => void;
  assessmentId?: string;
  selectedUids: string[];
  device?: string;
}) {
  const [query, setQuery] = useState("");
  const id = useId();
  const result = useQuery({
    queryKey: ["assessment-options", snapshot, kind, query, assessmentId, device],
    queryFn: () =>
      api<DiscoveryResponse>(optionsPath(snapshot, kind, query, assessmentId, undefined, device)),
    enabled: !!snapshot,
  });
  const items = result.data?.items ?? [];
  return (
    <div className="assessment-picker">
      <label className="assessment-field" htmlFor={id}>
        <span>{label}</span>
        <input
          id={id}
          type="search"
          value={query}
          disabled={!snapshot}
          placeholder={
            kind === "identity" || kind === "segment" || device ? "Search name" : "Search name, device or site"
          }
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>
      {!snapshot ? (
        <p>No snapshot selected</p>
      ) : result.isPending ? (
        <p role="status">Loading recorded objects</p>
      ) : result.isError ? (
        <p role="alert">
          Could not load recorded objects{" "}
          <button type="button" onClick={() => void result.refetch()}>
            Retry object search
          </button>
        </p>
      ) : (
        <>
          <ul className="assessment-picker-results" aria-label={`${label} results`}>
            {items.map((item) => (
              <li key={item.uid}>
                <button
                  type="button"
                  aria-label={[
                    item.name,
                    objectDescription(item),
                    selectedUids.includes(item.uid) ? "Selected" : "",
                  ]
                    .filter(Boolean)
                    .join(" ")}
                  disabled={!item.selectable || selectedUids.includes(item.uid)}
                  onClick={() => onSelect(item)}
                >
                  <strong>{item.name}</strong>
                  {objectDescription(item) && <span> {objectDescription(item)}</span>}
                  {selectedUids.includes(item.uid) && <span> Selected</span>}
                </button>
                {item.suggested && (
                  <p className="assessment-note">
                    Suggested: {item.suggestion_reason || "Related to this assessment"}
                  </p>
                )}
                {!item.selectable && (
                  <p>{item.disabled_reason || "Recorded relationships incomplete"}</p>
                )}
                <details>
                  <summary>Object details</summary>
                  <code>{item.uid}</code>
                  {!!item.interfaces?.length && (
                    <p>{item.interfaces.length} recorded endpoint interfaces</p>
                  )}
                </details>
              </li>
            ))}
          </ul>
          {!items.length && (
            <p>
              No matching {PLURAL[kind] ?? `${kind}s`} recorded in this snapshot
            </p>
          )}
          {result.data?.truncated && <p role="status">More matches exist</p>}
        </>
      )}
    </div>
  );
}
