import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { SnapshotList } from "../../api/types";
import { objectDescription, optionsPath, type DiscoveryResponse } from "../../assessments/guided";
import { ObjectPicker } from "../../assessments/ObjectPicker";

/** The inventory kinds of a member that the search finds, in the `kind` of GET /assessment-options. */
export const MEMBER_KINDS = ["device", "interface", "ip", "network"] as const;
export type MemberKind = (typeof MEMBER_KINDS)[number];
/** The kinds of the first search. The interfaces of a device have a search of their own. */
const SEARCH_KINDS: readonly MemberKind[] = ["device", "ip", "network"];

export const MEMBER_KIND_LABEL: Record<MemberKind, string> = {
  device: "device",
  interface: "interface",
  ip: "IP address",
  network: "network",
};

export interface FoundMember {
  uid: string;
  name: string;
  kind: MemberKind;
}

/** `snapshot`, or the current snapshot when `snapshot` is empty. */
export function useMemberSnapshot(snapshot: string): string {
  const snapshots = useQuery({ queryKey: ["snapshots"], queryFn: () => api<SnapshotList>("/snapshots") });
  const current = snapshots.data?.current;
  return snapshot || (current != null ? String(current) : "");
}

/**
 * A search of the devices, IP addresses and networks at `snapshot`. A selected
 * device opens a search of its interfaces.
 */
export function MemberSearch({
  snapshot,
  selected,
  onSelect,
}: {
  snapshot: string;
  selected: string | null;
  onSelect: (item: FoundMember) => void;
}) {
  const [device, setDevice] = useState<FoundMember | null>(null);
  if (device)
    return (
      <div className="assessment-interface-picker">
        <p>
          Device <strong>{device.name}</strong>{" "}
          <button type="button" onClick={() => setDevice(null)}>
            Change device
          </button>
        </p>
        <ObjectPicker
          snapshot={snapshot}
          kind="interface"
          device={device.uid}
          label="Find interface"
          selectedUids={selected && selected !== device.uid ? [selected] : []}
          onSelect={(item) => onSelect({ uid: item.uid, name: item.name, kind: "interface" })}
        />
      </div>
    );
  return (
    <ObjectSearch
      snapshot={snapshot}
      selected={selected}
      onSelect={(item) => {
        onSelect(item);
        if (item.kind === "device") setDevice(item);
      }}
    />
  );
}

function ObjectSearch({
  snapshot,
  selected,
  onSelect,
}: {
  snapshot: string;
  selected: string | null;
  onSelect: (item: FoundMember) => void;
}) {
  const [query, setQuery] = useState("");
  const id = useId();
  const result = useQuery({
    queryKey: ["assessment-options", snapshot, SEARCH_KINDS.join(","), query],
    queryFn: () => api<DiscoveryResponse>(optionsPath(snapshot, SEARCH_KINDS.join(","), query)),
    enabled: !!snapshot,
  });
  const items = (result.data?.items ?? []).filter((item): item is typeof item & { kind: MemberKind } =>
    (SEARCH_KINDS as readonly string[]).includes(item.kind),
  );
  return (
    <div className="assessment-picker">
      <label className="assessment-field" htmlFor={id}>
        <span>Find member</span>
        <input
          id={id}
          type="search"
          value={query}
          disabled={!snapshot}
          placeholder="Search name, address or site"
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>
      {snapshot &&
        (result.isPending ? (
          <p role="status">Loading recorded objects</p>
        ) : result.isError ? (
          <p role="alert">
            Could not load recorded objects{" "}
            <button type="button" onClick={() => void result.refetch()}>
              Retry member search
            </button>
          </p>
        ) : (
          <>
            <ul className="assessment-picker-results" aria-label="Member results">
              {items.map((item) => {
                const description = objectDescription(item);
                return (
                  <li key={`${item.kind}:${item.uid}`}>
                    <button
                      type="button"
                      aria-pressed={selected === item.uid}
                      disabled={!item.selectable}
                      onClick={() => onSelect({ uid: item.uid, name: item.name, kind: item.kind })}
                    >
                      <strong>{item.name}</strong> <span>{MEMBER_KIND_LABEL[item.kind]}</span>
                      {description && <span> {description}</span>}
                    </button>
                  </li>
                );
              })}
            </ul>
            {!items.length && <p>No matching objects</p>}
            {result.data?.truncated && <p role="status">More matches exist</p>}
          </>
        ))}
    </div>
  );
}
