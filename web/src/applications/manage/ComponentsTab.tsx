import { lazy, Suspense, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { PinnedSnapshotPicker } from "../../assessments/PinnedSnapshotPicker";
import { GroupFields } from "../ApplicationEditor";
import { memberSource, memberStateOf } from "../structureModel";
import type { ApplicationMember, ApplicationRevision, InventoryReference, ResolvedApplication } from "../types";
import { nextId, type ApplicationDraft } from "../useApplicationDraft";
import { groupName, portText } from "./connectionText";
import { MemberSearch, useMemberSnapshot, type FoundMember } from "./MemberSearch";

const ComponentGraph = lazy(() => import("./ComponentGraph"));

/** The state of a group at a resolution: "resolved" when every member resolved, else the count of each other state. */
function groupState(states: Array<string | null>): string {
  const known = states.filter((state): state is string => state != null);
  if (known.length === 0) return "";
  const counts = new Map<string, number>();
  for (const state of known) if (state !== "resolved") counts.set(state, (counts.get(state) ?? 0) + 1);
  if (counts.size === 0) return "resolved";
  return [...counts].map(([state, count]) => `${count} ${state}`).join(", ");
}

export function ComponentsTab({
  record,
  editor,
  locked,
}: {
  record: ApplicationRevision;
  editor: ApplicationDraft;
  locked: boolean;
}) {
  const { draft } = editor;
  const [selected, setSelected] = useState<number | null>(null);
  const [snapshot, setSnapshot] = useState("");
  const connectionIds = record.definition.connections.map((item) => item.id);
  const resolution = useQuery({
    queryKey: ["business-application-resolution", record.id, snapshot, connectionIds],
    queryFn: () =>
      api<ResolvedApplication>(`/business-applications/${encodeURIComponent(record.id)}/resolve`, {
        method: "POST",
        body: { snapshot, connection_ids: connectionIds },
      }),
    enabled: !locked && !!snapshot && connectionIds.length > 0,
  });
  const memberState = memberStateOf(resolution.data);
  const group = selected != null ? draft.groups[selected] : undefined;

  return (
    <div className="apps-split">
      <section aria-label="Components">
        <div className="apps-section-head">
          <h2>Components</h2>
          <button
            type="button"
            className="secondary"
            disabled={locked}
            onClick={() => {
              editor.addGroup();
              setSelected(draft.groups.length);
            }}
          >
            Add component
          </button>
        </div>
        <PinnedSnapshotPicker label="Snapshot" value={snapshot} onChange={setSnapshot} />
        <Suspense fallback={<p className="hint" role="status">Loading the graph</p>}>
          <ComponentGraph
            definition={draft}
            selected={group?.id ?? null}
            onSelect={(id) => setSelected(draft.groups.findIndex((item) => item.id === id))}
          />
        </Suspense>
        {resolution.isError && <p role="alert">Could not resolve the components</p>}
        <div className="results inv-table">
          <table>
            <thead>
              <tr>
                <th>Component</th>
                <th>Members</th>
                {snapshot && <th>Resolved at {snapshot}</th>}
                <th>Connections</th>
              </tr>
            </thead>
            <tbody>
              {draft.groups.map((item, index) => (
                <tr key={index} aria-selected={index === selected}>
                  <td>
                    <button
                      type="button"
                      className="linkish"
                      aria-pressed={index === selected}
                      onClick={() => setSelected(index)}
                    >
                      {item.name}
                    </button>
                  </td>
                  <td>{item.members.map((member) => member.name ?? member.id).join(", ")}</td>
                  {snapshot && (
                    <td>{groupState(item.members.map((member) => memberState(item.id, member.id)))}</td>
                  )}
                  <td>
                    {
                      draft.connections.filter(
                        (connection) => connection.source === item.id || connection.destination === item.id,
                      ).length
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      {group && selected != null && (
        <aside className="apps-form" aria-label={`Component ${group.name}`}>
          <div className="apps-section-head">
            <h2>{group.name}</h2>
            <button
              type="button"
              className="secondary"
              disabled={locked}
              onClick={() => {
                editor.removeGroup(selected);
                setSelected(null);
              }}
            >
              Delete component
            </button>
          </div>
          <fieldset disabled={locked}>
            <div className="apps-used-by">
              <span>Used by</span>
              <span>
                {draft.connections
                  .filter((connection) => connection.source === group.id || connection.destination === group.id)
                  .map(
                    (connection) =>
                      `${groupName(draft, connection.source)} to ${groupName(draft, connection.destination)} ${portText(connection)}`,
                  )
                  .join(", ") || "none"}
              </span>
            </div>
            <GroupFields
              group={group}
              definition={draft}
              snapshot={snapshot}
              addButton={false}
              onChange={(value) => editor.replaceGroup(selected, value)}
              memberExtra={(member) => {
                const state = memberState(group.id, member.id);
                return state ? <p className="apps-member-state">{memberSource(member)}, {state}</p> : null;
              }}
            />
            <AddMember
              snapshot={snapshot}
              members={group.members}
              onAdd={(member) => editor.replaceGroup(selected, { ...group, members: [...group.members, member] })}
            />
          </fieldset>
        </aside>
      )}
    </div>
  );
}

function AddMember({
  snapshot,
  members,
  onAdd,
}: {
  snapshot: string;
  members: ApplicationMember[];
  onAdd: (member: ApplicationMember) => void;
}) {
  const [mode, setMode] = useState<"inventory" | "address">("inventory");
  const [found, setFound] = useState<FoundMember | null>(null);
  const [address, setAddress] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<InventoryReference["role"]>("component");
  const searchSnapshot = useMemberSnapshot(snapshot);
  const ready = mode === "inventory" ? !!found : !!address.trim();

  function add() {
    const id = nextId("member", members);
    const label = name.trim() || (mode === "inventory" ? found?.name : undefined);
    onAdd(
      mode === "inventory"
        ? { id, ...(label ? { name: label } : {}), inventory: { kind: found!.kind, uid: found!.uid, role } }
        : { id, ...(label ? { name: label } : {}), address: address.trim() },
    );
    setFound(null);
    setAddress("");
    setName("");
  }

  return (
    <section aria-label="Add member">
      <h3>Add member</h3>
      <div className="application-structure-mode" role="group" aria-label="Member source">
        <button type="button" aria-pressed={mode === "inventory"} onClick={() => setMode("inventory")}>
          From inventory
        </button>
        <button type="button" aria-pressed={mode === "address"} onClick={() => setMode("address")}>
          Address or network
        </button>
      </div>
      {mode === "inventory" ? (
        <MemberSearch snapshot={searchSnapshot} selected={found?.uid ?? null} onSelect={setFound} />
      ) : (
        <label className="inv-field">
          <span>Address or network</span>
          <input value={address} onChange={(event) => setAddress(event.target.value)} />
        </label>
      )}
      <div className="application-fields">
        <label>
          Name
          <input value={name} placeholder={found?.name} onChange={(event) => setName(event.target.value)} />
        </label>
        {mode === "inventory" && (
          <label>
            Role
            <select value={role} onChange={(event) => setRole(event.target.value as typeof role)}>
              <option value="component">Component</option>
              <option value="source">Source</option>
              <option value="destination">Destination</option>
              <option value="shared">Shared</option>
            </select>
          </label>
        )}
      </div>
      <button type="button" className="secondary" disabled={!ready} onClick={add}>
        Add member
      </button>
    </section>
  );
}
