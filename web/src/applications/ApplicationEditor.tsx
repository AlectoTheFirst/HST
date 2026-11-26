import { useState } from "react";
import { ApiError, api } from "../api/client";
import { MtuRequirementFields } from "../assessments/MtuRequirementFields";
import { ObjectPicker } from "../assessments/ObjectPicker";
import { PinnedSnapshotPicker } from "../assessments/PinnedSnapshotPicker";
import { ConditionEditor } from "../assessments/RequirementComposer";
import type { Condition } from "../assessments/types";
import type {
  ApplicationConnection,
  ApplicationMember,
  ApplicationRevision,
  ApplicationService,
  BusinessApplicationDefinition,
  ComponentGroup,
  DestinationCondition,
  EndpointContext,
  InventoryReference,
  Placeholder,
} from "./types";

const identifier = (value: string) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^[^a-z]+/, "")
    .slice(0, 63);
const ports = (value: string): Array<number | string> | null => {
  const values = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => (/^\d+$/.test(item) ? Number(item) : item));
  return values.length ? values : null;
};

/** The empty definition that the editor creates an application from. */
export function newApplication(): ApplicationRevision {
  return {
    id: "",
    revision: 0,
    name: "",
    digest: "",
    created_by: null,
    created_at: "",
    definition: {
      schema_version: 1,
      kind: "BusinessApplication",
      id: "",
      name: "",
      state: "draft",
      services: [],
      groups: [],
      connections: [],
    },
  };
}

export function toCondition(value: DestinationCondition): Condition {
  return {
    kind: value.kind,
    ...(value.member != null ? { member: value.member } : {}),
    ...(value.n != null ? { n: value.n } : {}),
    ...(value.kind !== "member" ? { parts: (value.parts ?? []).map(toCondition) } : {}),
  };
}

function fromCondition(value: Condition): DestinationCondition {
  return {
    kind: value.kind,
    ...(value.member !== undefined ? { member: value.member } : {}),
    ...(value.n !== undefined ? { n: value.n } : {}),
    parts: (value.parts ?? []).map(fromCondition),
  };
}

function renameMember(
  value: DestinationCondition,
  from: string,
  to: string,
): DestinationCondition {
  if (value.kind === "member") return value.member === from ? { ...value, member: to } : value;
  return { ...value, parts: (value.parts ?? []).map((part) => renameMember(part, from, to)) };
}

function nextId(prefix: string, values: Array<{ id: string }>): string {
  let index = values.length + 1;
  while (values.some((item) => item.id === `${prefix}-${index}`)) index += 1;
  return `${prefix}-${index}`;
}

export function changedAreas(
  left: BusinessApplicationDefinition,
  right: BusinessApplicationDefinition,
): string[] {
  const areas: string[] = [];
  for (const key of ["name", "description", "owner", "environment", "state"] as const) {
    if (JSON.stringify(left[key]) !== JSON.stringify(right[key])) areas.push(key);
  }
  for (const key of ["services", "groups", "connections"] as const) {
    const before = new Map(left[key].map((item) => [item.id, JSON.stringify(item)]));
    const after = new Map(right[key].map((item) => [item.id, JSON.stringify(item)]));
    const ids = new Set([...before.keys(), ...after.keys()]);
    for (const id of ids) if (before.get(id) !== after.get(id)) areas.push(`${key}.${id}`);
  }
  return areas;
}

function rebaseDraft(
  base: BusinessApplicationDefinition,
  local: BusinessApplicationDefinition,
  remote: BusinessApplicationDefinition,
): BusinessApplicationDefinition {
  const result = structuredClone(remote);
  for (const key of ["name", "description", "owner", "environment", "state"] as const) {
    if (JSON.stringify(local[key]) !== JSON.stringify(base[key]))
      (result[key] as unknown) = local[key];
  }
  for (const key of ["services", "groups", "connections"] as const) {
    const baseById = new Map(base[key].map((item) => [item.id, item]));
    const localById = new Map(local[key].map((item) => [item.id, item]));
    const remoteValues = result[key] as Array<{ id: string }>;
    const merged = remoteValues
      .filter((item) => localById.has(item.id) || !baseById.has(item.id))
      .map((item) => {
        const localItem = localById.get(item.id);
        const baseItem = baseById.get(item.id);
        return localItem && JSON.stringify(localItem) !== JSON.stringify(baseItem)
          ? localItem
          : item;
      });
    for (const item of local[key])
      if (!baseById.has(item.id) && !merged.some((entry) => entry.id === item.id))
        merged.push(item);
    (result[key] as Array<{ id: string }>) = merged;
  }
  return result;
}

export function ApplicationEditor({
  record,
  canEdit,
  onSaved,
}: {
  record: ApplicationRevision;
  canEdit: boolean;
  onSaved: (record: ApplicationRevision) => void;
}) {
  const [draft, setDraft] = useState<BusinessApplicationDefinition>(() =>
    structuredClone(record.definition),
  );
  const [base, setBase] = useState(record);
  const [conflict, setConflict] = useState<ApplicationRevision | null>(null);
  const [inventorySnapshot, setInventorySnapshot] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const isNew = base.revision === 0;
  const dirty = JSON.stringify(draft) !== JSON.stringify(base.definition);
  const placeholders = draft.groups.some((group) =>
    group.members.some((member) => member.placeholder),
  );

  function update<K extends keyof BusinessApplicationDefinition>(
    key: K,
    value: BusinessApplicationDefinition[K],
  ) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function addService() {
    const id = nextId("service", draft.services);
    update("services", [
      ...draft.services,
      { id, name: `Service ${draft.services.length + 1}`, connection_ids: [], component_roles: [] },
    ]);
  }

  function addGroup() {
    const id = nextId("group", draft.groups);
    update("groups", [
      ...draft.groups,
      { id, name: `Component group ${draft.groups.length + 1}`, members: [] },
    ]);
  }

  function addConnection() {
    const id = nextId("connection", draft.connections);
    const source = draft.groups[0]?.id ?? "";
    const destination = draft.groups[1]?.id ?? source;
    const member =
      draft.groups.find((group) => group.id === destination)?.members[0]?.id ??
      "destination-member";
    update("connections", [
      ...draft.connections,
      {
        id,
        name: `Connection ${draft.connections.length + 1}`,
        source,
        destination,
        success: "forward",
        destination_condition: { kind: "member", member, parts: [] },
        header_constraints: {},
      },
    ]);
  }

  function replaceService(index: number, value: ApplicationService) {
    update(
      "services",
      draft.services.map((item, i) => (i === index ? value : item)),
    );
  }

  /** A changed group or member id is renamed in the connections and the
   *  component roles that reference it. */
  function replaceGroup(index: number, value: ComponentGroup) {
    const before = draft.groups[index];
    const members = new Map<string, string>();
    if (before.members.length === value.members.length)
      before.members.forEach((member, i) => {
        if (member.id !== value.members[i].id) members.set(member.id, value.members[i].id);
      });
    const group = (id: string) => (id === before.id ? value.id : id);
    setDraft((current) => ({
      ...current,
      groups: current.groups.map((item, i) => (i === index ? value : item)),
      services: current.services.map((service) => ({
        ...service,
        component_roles: service.component_roles.map((entry) => ({
          ...entry,
          group_id: group(entry.group_id),
        })),
      })),
      connections: current.connections.map((connection) => {
        let condition = connection.destination_condition;
        if (connection.destination === before.id)
          for (const [from, to] of members) condition = renameMember(condition, from, to);
        return {
          ...connection,
          source: group(connection.source),
          destination: group(connection.destination),
          destination_condition: condition,
        };
      }),
    }));
  }

  /** A changed connection id is renamed in the services. */
  function replaceConnection(index: number, value: ApplicationConnection) {
    const before = draft.connections[index];
    setDraft((current) => ({
      ...current,
      connections: current.connections.map((item, i) => (i === index ? value : item)),
      services: current.services.map((service) => ({
        ...service,
        connection_ids: service.connection_ids.map((id) => (id === before.id ? value.id : id)),
      })),
    }));
  }

  async function save() {
    setBusy(true);
    setError("");
    try {
      const saved = await api<ApplicationRevision>(
        isNew
          ? "/business-applications"
          : `/business-applications/${encodeURIComponent(record.id)}`,
        {
          method: isNew ? "POST" : "PUT",
          body: { definition: draft, expected_revision: base.revision, source: "editor" },
        },
      );
      onSaved(saved);
    } catch (cause) {
      if (!isNew && cause instanceof ApiError && cause.status === 409) {
        const latest = await api<{ application: ApplicationRevision }>(
          `/business-applications/${encodeURIComponent(record.id)}`,
        );
        setConflict(latest.application);
        setError("The application has a newer revision");
      } else setError(cause instanceof Error ? cause.message : "Could not save the application");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="application-editor" aria-label="Visual application editor">
      <div className="application-section-heading">
        <div>
          <h3>Visual editor</h3>
        </div>
        {dirty && <span role="status">Unsaved changes</span>}
      </div>
      <fieldset disabled={!canEdit || busy}>
        <legend>Application metadata</legend>
        <div className="application-fields">
          <label>
            Name
            <input
              required
              value={draft.name}
              onChange={(event) => update("name", event.target.value)}
            />
          </label>
          <IdInput
            label="Stable ID"
            value={draft.id}
            disabled={!isNew}
            onCommit={(id) => update("id", id)}
          />
          <label>
            Environment
            <input
              value={draft.environment ?? ""}
              onChange={(event) => update("environment", event.target.value || null)}
            />
          </label>
          <label>
            Owner
            <input
              value={draft.owner ?? ""}
              onChange={(event) => update("owner", event.target.value || null)}
            />
          </label>
          <label>
            Catalog state
            <select
              value={draft.state}
              onChange={(event) => update("state", event.target.value as "draft" | "ready")}
            >
              <option value="draft">Draft</option>
              <option value="ready" disabled={placeholders}>
                Ready intent
              </option>
            </select>
          </label>
        </div>
        <label>
          Description
          <textarea
            rows={2}
            value={draft.description ?? ""}
            onChange={(event) => update("description", event.target.value || null)}
          />
        </label>
      </fieldset>

      <fieldset disabled={!canEdit || busy}>
        <legend>Services</legend>
        {draft.services.map((service, index) => (
          <article className="application-edit-card" key={index}>
            <div className="application-fields">
              <label>
                Name
                <input
                  value={service.name}
                  onChange={(event) =>
                    replaceService(index, { ...service, name: event.target.value })
                  }
                />
              </label>
              <IdInput
                label="Stable ID"
                value={service.id}
                taken={draft.services.map((item) => item.id)}
                onCommit={(id) => replaceService(index, { ...service, id })}
              />
            </div>
            <span>Associated connections</span>
            <div className="application-checks">
              {draft.connections.map((connection) => (
                <label key={connection.id}>
                  <input
                    type="checkbox"
                    checked={service.connection_ids.includes(connection.id)}
                    onChange={(event) =>
                      replaceService(index, {
                        ...service,
                        connection_ids: event.target.checked
                          ? [...service.connection_ids, connection.id]
                          : service.connection_ids.filter((id) => id !== connection.id),
                      })
                    }
                  />
                  {connection.name}
                </label>
              ))}
            </div>
            <span>Component roles</span>
            {service.component_roles.map((entry, roleIndex) => {
              const roles = (value: ApplicationService["component_roles"][number]) =>
                replaceService(index, {
                  ...service,
                  component_roles: service.component_roles.map((item, i) =>
                    i === roleIndex ? value : item,
                  ),
                });
              return (
                <div className="application-fields" key={roleIndex}>
                  <label>
                    Component group
                    <select
                      value={entry.group_id}
                      onChange={(event) => roles({ ...entry, group_id: event.target.value })}
                    >
                      {draft.groups.map((group) => (
                        <option key={group.id} value={group.id}>
                          {group.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Role
                    <select
                      value={entry.role}
                      onChange={(event) =>
                        roles({ ...entry, role: event.target.value as typeof entry.role })
                      }
                    >
                      <option value="client">Client</option>
                      <option value="endpoint">Endpoint</option>
                      <option value="dependency">Dependency</option>
                      <option value="component">Component</option>
                    </select>
                  </label>
                  <button
                    type="button"
                    onClick={() =>
                      replaceService(index, {
                        ...service,
                        component_roles: service.component_roles.filter((_, i) => i !== roleIndex),
                      })
                    }
                  >
                    Remove component role
                  </button>
                </div>
              );
            })}
            <button
              type="button"
              disabled={draft.groups.length === 0}
              onClick={() =>
                replaceService(index, {
                  ...service,
                  component_roles: [
                    ...service.component_roles,
                    { group_id: draft.groups[0].id, role: "component" },
                  ],
                })
              }
            >
              Add component role
            </button>
            <button
              type="button"
              onClick={() =>
                update(
                  "services",
                  draft.services.filter((_, i) => i !== index),
                )
              }
            >
              Remove service
            </button>
          </article>
        ))}
        <button type="button" onClick={addService}>
          Add service
        </button>
      </fieldset>

      <fieldset disabled={!canEdit || busy}>
        <legend>Component groups</legend>
        <PinnedSnapshotPicker
          label="Inventory snapshot"
          value={inventorySnapshot}
          onChange={setInventorySnapshot}
        />
        {draft.groups.map((group, groupIndex) => {
          const affected = draft.connections.filter(
            (connection) => connection.source === group.id || connection.destination === group.id,
          );
          return (
            <article className="application-edit-card" key={groupIndex}>
              <div className="application-fields">
                <label>
                  Name
                  <input
                    value={group.name}
                    onChange={(event) =>
                      replaceGroup(groupIndex, { ...group, name: event.target.value })
                    }
                  />
                </label>
                <IdInput
                  label="Stable ID"
                  value={group.id}
                  taken={draft.groups.map((item) => item.id)}
                  onCommit={(id) => replaceGroup(groupIndex, { ...group, id })}
                />
              </div>
              {affected.length > 0 && <p>Affects {affected.map((item) => item.name).join(", ")}</p>}
              {group.members.map((member, memberIndex) => (
                <MemberEditor
                  key={memberIndex}
                  member={member}
                  taken={group.members.map((item) => item.id)}
                  snapshot={inventorySnapshot}
                  onChange={(value) =>
                    replaceGroup(groupIndex, {
                      ...group,
                      members: group.members.map((item, i) => (i === memberIndex ? value : item)),
                    })
                  }
                  onRemove={() =>
                    replaceGroup(groupIndex, {
                      ...group,
                      members: group.members.filter((_, i) => i !== memberIndex),
                    })
                  }
                />
              ))}
              <button
                type="button"
                onClick={() =>
                  replaceGroup(groupIndex, {
                    ...group,
                    members: [
                      ...group.members,
                      { id: nextId("member", group.members), address: "192.0.2.1" },
                    ],
                  })
                }
              >
                Add member
              </button>
              <button
                type="button"
                onClick={() =>
                  update(
                    "groups",
                    draft.groups.filter((_, i) => i !== groupIndex),
                  )
                }
              >
                Remove group
              </button>
            </article>
          );
        })}
        <button type="button" onClick={addGroup}>
          Add component group
        </button>
      </fieldset>

      <fieldset disabled={!canEdit || busy}>
        <legend>Connections</legend>
        {draft.connections.map((connection, index) => (
          <article className="application-edit-card" key={index}>
            <div className="application-fields">
              <label>
                Name
                <input
                  value={connection.name}
                  onChange={(event) =>
                    replaceConnection(index, { ...connection, name: event.target.value })
                  }
                />
              </label>
              <IdInput
                label="Stable ID"
                value={connection.id}
                taken={draft.connections.map((item) => item.id)}
                onCommit={(id) => replaceConnection(index, { ...connection, id })}
              />
              <label>
                Source
                <select
                  value={connection.source}
                  onChange={(event) =>
                    replaceConnection(index, { ...connection, source: event.target.value })
                  }
                >
                  {draft.groups.map((group) => (
                    <option key={group.id} value={group.id}>
                      {group.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Destination
                <select
                  value={connection.destination}
                  onChange={(event) => {
                    const destination = event.target.value;
                    const member =
                      draft.groups.find((group) => group.id === destination)?.members[0]?.id ?? "";
                    replaceConnection(index, {
                      ...connection,
                      destination,
                      destination_condition:
                        connection.destination_condition.kind === "member"
                          ? { kind: "member", member, parts: [] }
                          : connection.destination_condition,
                    });
                  }}
                >
                  {draft.groups.map((group) => (
                    <option key={group.id} value={group.id}>
                      {group.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Protocol
                <input
                  value={connection.protocol ?? ""}
                  onChange={(event) =>
                    replaceConnection(index, {
                      ...connection,
                      protocol: event.target.value || null,
                    })
                  }
                />
              </label>
              <label>
                Destination ports
                <input
                  value={(connection.destination_ports ?? []).join(", ")}
                  onChange={(event) =>
                    replaceConnection(index, {
                      ...connection,
                      destination_ports: ports(event.target.value),
                    })
                  }
                />
              </label>
              <label>
                Source ports
                <input
                  value={(connection.source_ports ?? []).join(", ")}
                  onChange={(event) =>
                    replaceConnection(index, {
                      ...connection,
                      source_ports: ports(event.target.value),
                    })
                  }
                />
              </label>
              <label>
                Required behavior
                <select
                  value={connection.success}
                  onChange={(event) =>
                    replaceConnection(index, {
                      ...connection,
                      success: event.target.value as ApplicationConnection["success"],
                    })
                  }
                >
                  <option value="forward">Forward</option>
                  <option value="round-trip">Round trip</option>
                  <option value="session">Session</option>
                </select>
              </label>
              {connection.destination_condition.kind === "member" && (
                <label>
                  Required destination
                  <select
                    value={connection.destination_condition.member ?? ""}
                    onChange={(event) =>
                      replaceConnection(index, {
                        ...connection,
                        destination_condition: {
                          kind: "member",
                          member: event.target.value,
                          parts: [],
                        },
                      })
                    }
                  >
                    {draft.groups
                      .find((group) => group.id === connection.destination)
                      ?.members.map((member) => (
                        <option key={member.id} value={member.id}>
                          {member.name ?? member.id}
                        </option>
                      ))}
                  </select>
                </label>
              )}
            </div>
            <ConditionEditor
              legend="Destination condition"
              rootMember={false}
              value={toCondition(connection.destination_condition)}
              members={(
                draft.groups.find((group) => group.id === connection.destination)?.members ?? []
              ).map((member) => ({ value: member.id, label: member.name ?? member.id }))}
              onChange={(condition) =>
                replaceConnection(index, {
                  ...connection,
                  destination_condition: fromCondition(condition),
                })
              }
            />
            {(["source", "destination"] as const).map((end) => (
              <ContextEditor
                key={end}
                end={end}
                snapshot={inventorySnapshot}
                value={connection[`${end}_context`]}
                onChange={(context) =>
                  replaceConnection(index, { ...connection, [`${end}_context`]: context })
                }
              />
            ))}
            <MtuRequirementFields
              value={connection.mtu}
              ipv6={ipv6Group(draft.groups.find((group) => group.id === connection.source))}
              onChange={(mtu) => replaceConnection(index, { ...connection, mtu })}
            />
            <button
              type="button"
              onClick={() =>
                update(
                  "connections",
                  draft.connections.filter((_, i) => i !== index),
                )
              }
            >
              Remove connection
            </button>
          </article>
        ))}
        <button type="button" disabled={draft.groups.length < 2} onClick={addConnection}>
          Add connection
        </button>
      </fieldset>
      <div className="assessment-actions">
        <button type="button" disabled={!canEdit || busy || !dirty} onClick={() => void save()}>
          {busy ? "Saving" : "Save revision"}
        </button>
        <button
          type="button"
          disabled={!dirty || busy}
          onClick={() => {
            setDraft(structuredClone(base.definition));
            setConflict(null);
          }}
        >
          Discard draft
        </button>
      </div>
      {error && <p role="alert">{error}</p>}
      {conflict && (
        <section className="application-edit-card" aria-label="Revision conflict">
          <h4>Revision conflict</h4>
          <p>
            Current revision {conflict.revision} changed:{" "}
            {changedAreas(base.definition, conflict.definition).join(", ") || "revision metadata"}
          </p>
          <div className="assessment-actions">
            <button
              type="button"
              onClick={() => {
                setDraft(rebaseDraft(base.definition, draft, conflict.definition));
                setBase(conflict);
                setConflict(null);
                setError("Local edits rebased onto the current revision");
              }}
            >
              Rebase local edits
            </button>
            <button
              type="button"
              onClick={() => {
                setDraft(structuredClone(conflict.definition));
                setBase(conflict);
                setConflict(null);
                setError("");
              }}
            >
              Use current revision
            </button>
          </div>
          <details>
            <summary>Compare definitions</summary>
            <h5>Draft</h5>
            <pre>{JSON.stringify(draft, null, 2)}</pre>
            <h5>Current revision</h5>
            <pre>{JSON.stringify(conflict.definition, null, 2)}</pre>
          </details>
        </section>
      )}
    </section>
  );
}

function MemberEditor({
  member,
  taken,
  snapshot,
  onChange,
  onRemove,
}: {
  member: ApplicationMember;
  taken: string[];
  snapshot: string;
  onChange: (member: ApplicationMember) => void;
  onRemove: () => void;
}) {
  if (member.placeholder)
    return (
      <PlaceholderEditor
        member={member}
        taken={taken}
        placeholder={member.placeholder}
        onChange={onChange}
        onRemove={onRemove}
      />
    );
  const inventory = !!member.inventory;
  return (
    <div className="application-member">
      <IdInput
        label="Member ID"
        value={member.id}
        taken={taken}
        onCommit={(id) => onChange({ ...member, id })}
      />
      <label>
        Member name
        <input
          value={member.name ?? ""}
          onChange={(event) => onChange({ ...member, name: event.target.value || undefined })}
        />
      </label>
      <label>
        Source
        <select
          value={inventory ? "inventory" : "literal"}
          onChange={(event) =>
            onChange(
              event.target.value === "inventory"
                ? {
                    id: member.id,
                    name: member.name,
                    inventory: { kind: "interface", uid: "", role: "component" },
                  }
                : { id: member.id, name: member.name, address: "192.0.2.1" },
            )
          }
        >
          <option value="literal">Literal address or prefix</option>
          <option value="inventory">Inventory reference</option>
        </select>
      </label>
      {inventory ? (
        <>
          <label>
            Kind
            <select
              value={member.inventory!.kind}
              onChange={(event) =>
                onChange({
                  ...member,
                  inventory: {
                    ...member.inventory!,
                    kind: event.target.value as InventoryReferenceKind,
                  },
                })
              }
            >
              {(
                [
                  ["device", "Device"],
                  ["interface", "Interface"],
                  ["ip", "IP"],
                  ["network", "Network"],
                  ["dns", "DNS"],
                  ["service_requirement", "Service requirement"],
                  ["vrf", "VRF"],
                  ["identity", "Identity"],
                  ["segment", "Segment"],
                ] as const
              ).map(([kind, kindName]) => (
                <option key={kind} value={kind}>
                  {kindName}
                </option>
              ))}
            </select>
          </label>
          {(member.inventory!.kind === "device" || member.inventory!.kind === "interface") && (
            <ObjectPicker
              snapshot={snapshot}
              kind={member.inventory!.kind}
              label={`Find ${member.inventory!.kind}`}
              selectedUids={member.inventory!.uid ? [member.inventory!.uid] : []}
              onSelect={(item) =>
                onChange({
                  ...member,
                  name: member.name ?? item.name,
                  inventory: { ...member.inventory!, uid: item.uid },
                })
              }
            />
          )}
          <label>
            Role
            <select
              value={member.inventory!.role}
              onChange={(event) =>
                onChange({
                  ...member,
                  inventory: {
                    ...member.inventory!,
                    role: event.target.value as InventoryReference["role"],
                  },
                })
              }
            >
              <option value="source">Source</option>
              <option value="destination">Destination</option>
              <option value="component">Component</option>
              <option value="shared">Shared</option>
            </select>
          </label>
          <label>
            Inventory UID
            <input
              value={member.inventory!.uid}
              onChange={(event) =>
                onChange({
                  ...member,
                  inventory: { ...member.inventory!, uid: event.target.value },
                })
              }
            />
          </label>
          <label>
            Context
            <input
              value={member.inventory!.context ?? ""}
              onChange={(event) =>
                onChange({
                  ...member,
                  inventory: { ...member.inventory!, context: event.target.value || null },
                })
              }
            />
          </label>
        </>
      ) : (
        <>
          <label>
            Address or prefix
            <input
              value={member.address ?? ""}
              onChange={(event) => onChange({ ...member, address: event.target.value })}
            />
          </label>
          <label>
            Context
            <input
              value={member.context ?? ""}
              onChange={(event) => onChange({ ...member, context: event.target.value || null })}
            />
          </label>
        </>
      )}
      <button type="button" onClick={onRemove}>
        Remove member
      </button>
    </div>
  );
}

/**
 * A placeholder member of a schema version 2 definition. The form shows what
 * the placeholder describes. Bind replaces it with an inventory reference of
 * the expected kind to the selected candidate, whose fields are then edited as
 * for any inventory member. The member keeps its name and its context.
 */
function PlaceholderEditor({
  member,
  taken,
  placeholder,
  onChange,
  onRemove,
}: {
  member: ApplicationMember;
  taken: string[];
  placeholder: Placeholder;
  onChange: (member: ApplicationMember) => void;
  onRemove: () => void;
}) {
  const [chosen, setCandidate] = useState(placeholder.candidates[0] ?? "");
  const candidate = placeholder.candidates.includes(chosen)
    ? chosen
    : (placeholder.candidates[0] ?? "");
  const bind = () =>
    onChange({
      id: member.id,
      name: member.name,
      ...(member.context ? { context: member.context } : {}),
      inventory: {
        kind: placeholder.expected_kind ?? "interface",
        uid: candidate,
        role: "component",
      },
    });
  return (
    <div className="application-member" role="group" aria-label={`Placeholder ${member.id}`}>
      <IdInput
        label="Member ID"
        value={member.id}
        taken={taken}
        onCommit={(id) => onChange({ ...member, id })}
      />
      <p>
        {placeholder.status === "ambiguous" ? "Ambiguous placeholder" : "Unresolved placeholder"}:{" "}
        {placeholder.text}
        {placeholder.expected_kind ? ` (expected ${placeholder.expected_kind})` : ""}
      </p>
      {placeholder.note && <p>{placeholder.note}</p>}
      {placeholder.candidates.length > 0 && (
        <label>
          Candidate
          <select value={candidate} onChange={(event) => setCandidate(event.target.value)}>
            {placeholder.candidates.map((uid, index) => (
              <option key={index} value={uid}>
                {uid}
              </option>
            ))}
          </select>
        </label>
      )}
      <button type="button" onClick={bind}>
        Bind
      </button>
      <button type="button" onClick={onRemove}>
        Remove member
      </button>
    </div>
  );
}

type InventoryReferenceKind = NonNullable<ApplicationMember["inventory"]>["kind"];

/** The text is committed on blur. An empty text or an id in `taken` is
 *  reverted. */
function IdInput({
  label,
  value,
  taken = [],
  disabled,
  onCommit,
}: {
  label: string;
  value: string;
  taken?: string[];
  disabled?: boolean;
  onCommit: (value: string) => void;
}) {
  const [text, setText] = useState(value);
  const [previous, setPrevious] = useState(value);
  if (value !== previous) {
    setPrevious(value);
    setText(value);
  }
  return (
    <label>
      {label}
      <input
        required
        pattern="[a-z][a-z0-9-]*"
        value={text}
        disabled={disabled}
        onChange={(event) => setText(identifier(event.target.value))}
        onBlur={() => {
          if (text === value) return;
          if (!text || taken.includes(text)) setText(value);
          else onCommit(text);
        }}
      />
    </label>
  );
}

/** A source group whose literal members are all IPv6. */
function ipv6Group(group: ComponentGroup | undefined): boolean {
  const addresses = (group?.members ?? []).flatMap((member) =>
    member.address ? [member.address] : [],
  );
  return addresses.length > 0 && addresses.every((address) => address.includes(":"));
}

const END_TEXT = { source: "Source", destination: "Destination" } as const;

function ContextEditor({
  end,
  value,
  snapshot,
  onChange,
}: {
  end: "source" | "destination";
  value: EndpointContext | null | undefined;
  snapshot: string;
  onChange: (value: EndpointContext | undefined) => void;
}) {
  const name = END_TEXT[end];
  const [finding, setFinding] = useState<
    "device_uid" | "ingress_interface_uid" | "identity_uid" | "segment_uid" | null
  >(null);
  const set = (key: keyof EndpointContext, next: string | undefined) => {
    const context: EndpointContext = { ...value };
    if (next) context[key] = next;
    else delete context[key];
    onChange(Object.values(context).some((item) => item != null) ? context : undefined);
  };
  const selected = (key: keyof EndpointContext, text: string) =>
    value?.[key] && (
      <p>
        {name} {text} <code>{value[key]}</code>{" "}
        <button type="button" onClick={() => set(key, undefined)}>
          Remove {end} {text}
        </button>
      </p>
    );
  return (
    <fieldset>
      <legend>{name} context</legend>
      <label>
        {name} VRF
        <input value={value?.vrf ?? ""} onChange={(event) => set("vrf", event.target.value)} />
      </label>
      {(
        [
          ["device_uid", "device", "device"],
          ["ingress_interface_uid", "interface", "ingress interface"],
          ["identity_uid", "identity", "identity"],
          ["segment_uid", "segment", "segment"],
        ] as const
      ).map(([key, kind, text]) => (
        <div key={key}>
          {selected(key, text)}
          {finding === key ? (
            <ObjectPicker
              snapshot={snapshot}
              kind={kind}
              label={`Find ${end} ${text}`}
              selectedUids={value?.[key] ? [value[key]!] : []}
              onSelect={(item) => {
                set(key, item.uid);
                setFinding(null);
              }}
            />
          ) : (
            <button type="button" onClick={() => setFinding(key)}>
              Choose {end} {text}
            </button>
          )}
        </div>
      ))}
    </fieldset>
  );
}
