import { Fragment, useEffect, useState, type ReactNode } from "react";
import { MtuRequirementFields } from "../assessments/MtuRequirementFields";
import { ObjectPicker } from "../assessments/ObjectPicker";
import { PinnedSnapshotPicker } from "../assessments/PinnedSnapshotPicker";
import { ConditionEditor } from "../assessments/RequirementComposer";
import type { Condition } from "../assessments/types";
import { nextId, useApplicationDraft, type ApplicationDraft } from "./useApplicationDraft";
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
export const ports = (value: string): Array<number | string> | null => {
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

export function ApplicationEditor({
  record,
  canEdit,
  onSaved,
  onDirtyChange,
}: {
  record: ApplicationRevision;
  canEdit: boolean;
  onSaved: (record: ApplicationRevision) => void;
  onDirtyChange?: (dirty: boolean) => void;
}) {
  const editor = useApplicationDraft(record, onSaved);
  const { draft, busy, dirty } = editor;
  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);
  const [inventorySnapshot, setInventorySnapshot] = useState("");
  const locked = !canEdit || busy;

  return (
    <section className="application-editor" aria-label="Visual application editor">
      <div className="application-section-heading">
        <div>
          <h3>Visual editor</h3>
        </div>
        {dirty && <span role="status">Unsaved changes</span>}
      </div>
      <MetadataFields editor={editor} disabled={locked} />
      <ServicesFields editor={editor} disabled={locked} />

      <fieldset disabled={locked}>
        <legend>Component groups</legend>
        <PinnedSnapshotPicker
          label="Inventory snapshot"
          value={inventorySnapshot}
          onChange={setInventorySnapshot}
        />
        {draft.groups.map((group, groupIndex) => (
          <article className="application-edit-card" key={groupIndex}>
            <GroupFields
              group={group}
              definition={draft}
              snapshot={inventorySnapshot}
              onChange={(value) => editor.replaceGroup(groupIndex, value)}
            />
            <button type="button" onClick={() => editor.removeGroup(groupIndex)}>
              Remove group
            </button>
          </article>
        ))}
        <button type="button" onClick={editor.addGroup}>
          Add component group
        </button>
      </fieldset>

      <fieldset disabled={locked}>
        <legend>Connections</legend>
        {draft.connections.map((connection, index) => (
          <article className="application-edit-card" key={index}>
            <ConnectionFields
              connection={connection}
              definition={draft}
              snapshot={inventorySnapshot}
              onChange={(value) => editor.replaceConnection(index, value)}
            />
            <button type="button" onClick={() => editor.removeConnection(index)}>
              Remove connection
            </button>
          </article>
        ))}
        <button type="button" disabled={draft.groups.length < 2} onClick={editor.addConnection}>
          Add connection
        </button>
      </fieldset>
      <div className="assessment-actions">
        <button type="button" disabled={locked || !dirty} onClick={() => void editor.save()}>
          {busy ? "Saving" : "Save revision"}
        </button>
        <button type="button" disabled={!dirty || busy} onClick={editor.discard}>
          Discard draft
        </button>
      </div>
      <DraftConflict editor={editor} />
    </section>
  );
}

/** The error of the last save and the choices after a 409 conflict. */
export function DraftConflict({ editor }: { editor: ApplicationDraft }) {
  const { conflict, error, base, draft } = editor;
  return (
    <>
      {error && <p role="alert">{error}</p>}
      {conflict && (
        <section className="application-edit-card" aria-label="Revision conflict">
          <h4>Revision conflict</h4>
          <p>
            Current revision {conflict.revision} changed:{" "}
            {changedAreas(base.definition, conflict.definition).join(", ") || "revision metadata"}
          </p>
          <div className="assessment-actions">
            <button type="button" onClick={editor.rebase}>
              Rebase local edits
            </button>
            <button type="button" onClick={editor.takeCurrent}>
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
    </>
  );
}

export function MetadataFields({ editor, disabled }: { editor: ApplicationDraft; disabled: boolean }) {
  const { draft, update, isNew, placeholders } = editor;
  return (
    <fieldset disabled={disabled}>
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
  );
}

export function ServicesFields({ editor, disabled }: { editor: ApplicationDraft; disabled: boolean }) {
  const { draft, replaceService } = editor;
  return (
    <fieldset disabled={disabled}>
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
          <button type="button" onClick={() => editor.removeService(index)}>
            Remove service
          </button>
        </article>
      ))}
      <button type="button" onClick={editor.addService}>
        Add service
      </button>
    </fieldset>
  );
}

/** The name, id and members of a group. `memberExtra` renders after each member. */
export function GroupFields({
  group,
  definition,
  snapshot,
  onChange,
  memberExtra,
  addButton = true,
}: {
  group: ComponentGroup;
  definition: BusinessApplicationDefinition;
  snapshot: string;
  onChange: (group: ComponentGroup) => void;
  memberExtra?: (member: ApplicationMember) => ReactNode;
  addButton?: boolean;
}) {
  const affected = definition.connections.filter(
    (connection) => connection.source === group.id || connection.destination === group.id,
  );
  return (
    <>
      <div className="application-fields">
        <label>
          Name
          <input
            value={group.name}
            onChange={(event) => onChange({ ...group, name: event.target.value })}
          />
        </label>
        <IdInput
          label="Stable ID"
          value={group.id}
          taken={definition.groups.map((item) => item.id)}
          onCommit={(id) => onChange({ ...group, id })}
        />
      </div>
      {affected.length > 0 && <p>Affects {affected.map((item) => item.name).join(", ")}</p>}
      {group.members.map((member, memberIndex) => (
        <Fragment key={memberIndex}>
          <MemberEditor
            member={member}
            taken={group.members.map((item) => item.id)}
            snapshot={snapshot}
            onChange={(value) =>
              onChange({
                ...group,
                members: group.members.map((item, i) => (i === memberIndex ? value : item)),
              })
            }
            onRemove={() =>
              onChange({
                ...group,
                members: group.members.filter((_, i) => i !== memberIndex),
              })
            }
          />
          {memberExtra?.(member)}
        </Fragment>
      ))}
      {addButton && (
        <button
          type="button"
          onClick={() =>
            onChange({
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
      )}
    </>
  );
}

/** Every field of a connection: ends, ports, condition, contexts and MTU. */
export function ConnectionFields({
  connection,
  definition,
  snapshot,
  onChange,
}: {
  connection: ApplicationConnection;
  definition: BusinessApplicationDefinition;
  snapshot: string;
  onChange: (connection: ApplicationConnection) => void;
}) {
  const groups = definition.groups;
  return (
    <>
      <div className="application-fields">
        <label>
          Name
          <input
            value={connection.name}
            onChange={(event) => onChange({ ...connection, name: event.target.value })}
          />
        </label>
        <IdInput
          label="Stable ID"
          value={connection.id}
          taken={definition.connections.map((item) => item.id)}
          onCommit={(id) => onChange({ ...connection, id })}
        />
        <label>
          Source
          <select
            value={connection.source}
            onChange={(event) => onChange({ ...connection, source: event.target.value })}
          >
            {groups.map((group) => (
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
              const member = groups.find((group) => group.id === destination)?.members[0]?.id ?? "";
              onChange({
                ...connection,
                destination,
                destination_condition:
                  connection.destination_condition.kind === "member"
                    ? { kind: "member", member, parts: [] }
                    : connection.destination_condition,
              });
            }}
          >
            {groups.map((group) => (
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
            onChange={(event) => onChange({ ...connection, protocol: event.target.value || null })}
          />
        </label>
        <label>
          Destination ports
          <input
            value={(connection.destination_ports ?? []).join(", ")}
            onChange={(event) =>
              onChange({ ...connection, destination_ports: ports(event.target.value) })
            }
          />
        </label>
        <label>
          Source ports
          <input
            value={(connection.source_ports ?? []).join(", ")}
            onChange={(event) => onChange({ ...connection, source_ports: ports(event.target.value) })}
          />
        </label>
        <label>
          Required behavior
          <select
            value={connection.success}
            onChange={(event) =>
              onChange({
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
                onChange({
                  ...connection,
                  destination_condition: { kind: "member", member: event.target.value, parts: [] },
                })
              }
            >
              {groups
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
        members={(groups.find((group) => group.id === connection.destination)?.members ?? []).map(
          (member) => ({ value: member.id, label: member.name ?? member.id }),
        )}
        onChange={(condition) =>
          onChange({ ...connection, destination_condition: fromCondition(condition) })
        }
      />
      {(["source", "destination"] as const).map((end) => (
        <ContextEditor
          key={end}
          end={end}
          snapshot={snapshot}
          value={connection[`${end}_context`]}
          onChange={(context) => onChange({ ...connection, [`${end}_context`]: context })}
        />
      ))}
      <MtuRequirementFields
        value={connection.mtu}
        ipv6={ipv6Group(groups.find((group) => group.id === connection.source))}
        onChange={(mtu) => onChange({ ...connection, mtu })}
      />
    </>
  );
}

export function MemberEditor({
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
export function IdInput({
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

export function ContextEditor({
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
