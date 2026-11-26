import { useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  ApplicationConnection,
  ApplicationRevision,
  ApplicationService,
  BusinessApplicationDefinition,
  ComponentGroup,
  DestinationCondition,
} from "./types";

function renameMember(
  value: DestinationCondition,
  from: string,
  to: string,
): DestinationCondition {
  if (value.kind === "member") return value.member === from ? { ...value, member: to } : value;
  return { ...value, parts: (value.parts ?? []).map((part) => renameMember(part, from, to)) };
}

export function nextId(prefix: string, values: Array<{ id: string }>): string {
  let index = values.length + 1;
  while (values.some((item) => item.id === `${prefix}-${index}`)) index += 1;
  return `${prefix}-${index}`;
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

/** The unsaved definition of an application and the actions that change and save it.
 *  A revision 0 record is a new application, which `save` creates with POST. */
export function useApplicationDraft(
  record: ApplicationRevision,
  onSaved: (record: ApplicationRevision) => void,
) {
  const [draft, setDraft] = useState<BusinessApplicationDefinition>(() =>
    structuredClone(record.definition),
  );
  const [base, setBase] = useState(record);
  const [conflict, setConflict] = useState<ApplicationRevision | null>(null);
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
    return id;
  }

  function addGroup() {
    const id = nextId("group", draft.groups);
    update("groups", [
      ...draft.groups,
      { id, name: `Component group ${draft.groups.length + 1}`, members: [] },
    ]);
    return id;
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
    return id;
  }

  function replaceService(index: number, value: ApplicationService) {
    update(
      "services",
      draft.services.map((item, i) => (i === index ? value : item)),
    );
  }

  function removeService(index: number) {
    update(
      "services",
      draft.services.filter((_, i) => i !== index),
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

  function removeGroup(index: number) {
    update(
      "groups",
      draft.groups.filter((_, i) => i !== index),
    );
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

  function removeConnection(index: number) {
    update(
      "connections",
      draft.connections.filter((_, i) => i !== index),
    );
  }

  /** Puts a connection into one service, or into none with an empty `serviceId`. */
  function setConnectionService(connectionId: string, serviceId: string) {
    setDraft((current) => ({
      ...current,
      services: current.services.map((service) => {
        const ids = service.connection_ids.filter((id) => id !== connectionId);
        return { ...service, connection_ids: service.id === serviceId ? [...ids, connectionId] : ids };
      }),
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

  function discard() {
    setDraft(structuredClone(base.definition));
    setConflict(null);
  }

  function rebase() {
    if (!conflict) return;
    setDraft(rebaseDraft(base.definition, draft, conflict.definition));
    setBase(conflict);
    setConflict(null);
    setError("Local edits rebased onto the current revision");
  }

  function takeCurrent() {
    if (!conflict) return;
    setDraft(structuredClone(conflict.definition));
    setBase(conflict);
    setConflict(null);
    setError("");
  }

  return {
    draft,
    base,
    conflict,
    busy,
    error,
    isNew,
    dirty,
    placeholders,
    update,
    addService,
    addGroup,
    addConnection,
    replaceService,
    removeService,
    replaceGroup,
    removeGroup,
    replaceConnection,
    removeConnection,
    setConnectionService,
    save,
    discard,
    rebase,
    takeCurrent,
  };
}

export type ApplicationDraft = ReturnType<typeof useApplicationDraft>;
