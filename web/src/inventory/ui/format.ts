import type {
  Authority,
  CollectionState,
  Lifecycle,
  ObservationState,
  PlacementBasis,
  PlacementMode,
  PlacementState,
  PreviewMemberKind,
  PreviewOperation,
  ProfileOrigin,
  SortField,
} from "../../api/inventory";

export type Tone = "ok" | "warn" | "bad" | "neutral";
export type StateMap<K extends string> = Record<K, { label: string; tone: Tone }>;

export function formatTime(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "Never";
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString()} ${count === 1 ? one : many}`;
}

/** "last_success" and "auth.method" become "Last success" and "Auth method". */
export function humanize(key: string): string {
  const text = key.replaceAll("_", " ").replaceAll(".", " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** One display string for a scalar or structured setting value. */
export function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "None";
  if (value === "***") return "Hidden";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.length ? value.map(formatValue).join(", ") : "None";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** Nested objects as dotted keys, in one flat list. */
export function flatten(value: Record<string, unknown>, prefix = ""): Array<[string, unknown]> {
  return Object.entries(value).flatMap(([key, item]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return item && typeof item === "object" && !Array.isArray(item)
      ? flatten(item as Record<string, unknown>, path)
      : [[path, item] as [string, unknown]];
  });
}

export const COLLECTION_STATE: StateMap<CollectionState> = {
  current: { label: "Current", tone: "ok" },
  stale: { label: "Stale", tone: "warn" },
  partial: { label: "Partial", tone: "warn" },
  failed: { label: "Failed", tone: "bad" },
  never: { label: "Never collected", tone: "neutral" },
  manual: { label: "Manual collection", tone: "neutral" },
};

export const PLACEMENT_STATE: StateMap<PlacementState> = {
  assigned: { label: "Assigned", tone: "ok" },
  auto: { label: "Automatic", tone: "ok" },
  unplaced: { label: "Unplaced", tone: "neutral" },
  conflict: { label: "Conflict", tone: "bad" },
  stale: { label: "Stale", tone: "warn" },
  pending: { label: "Pending", tone: "warn" },
};

export const LIFECYCLE: StateMap<Lifecycle> = {
  active: { label: "Active", tone: "ok" },
  missing: { label: "Missing", tone: "warn" },
  archived: { label: "Archived", tone: "neutral" },
};

export const OBSERVATION: StateMap<ObservationState> = {
  current: { label: "Current", tone: "ok" },
  stale: { label: "Stale", tone: "warn" },
  absent: { label: "Absent", tone: "warn" },
};

export const AUTHORITY: StateMap<Authority> = {
  complete: { label: "Complete", tone: "neutral" },
  partial: { label: "Partial", tone: "warn" },
};

export const SORT_LABEL: Record<SortField, string> = {
  name: "Name",
  platform: "Platform",
  site: "Site",
  last_success: "Last success",
  collection_state: "Collection",
};

export const PLACEMENT_MODE: Record<PlacementMode, string> = {
  auto: "Automatic",
  assigned: "Assigned site",
  unplaced: "Unplaced",
};

export const PLACEMENT_BASIS: Record<PlacementBasis, string> = {
  assigned: "Assigned site",
  bound_locations: "Mapped reported locations",
  onboarding: "Onboarding site",
  none: "None",
};

export const PROFILE_ORIGIN: Record<ProfileOrigin, string> = {
  target: "Target profile",
  connection: "Connection profile",
  none: "No profile",
};

export const OPERATION_LABEL: Record<PreviewOperation, string> = {
  place_devices: "Change placement",
  assign_target_profile: "Assign target profile",
  edit_profile: "Edit profile",
  rotate_credential: "Rotate credential",
  delete_site: "Delete site",
  delete_connection: "Delete connection",
  delete_target: "Delete target",
  replace_target: "Replace target endpoint",
  edit_routing_members: "Change routing group members",
  archive_devices: "Archive devices",
  restore_devices: "Restore devices",
};

export const MEMBER_KIND: Record<PreviewMemberKind, string> = {
  device: "Device",
  target: "Target",
  connection: "Connection",
  profile: "Profile",
  credential: "Credential",
  site: "Site",
  routing_group: "Routing group",
};
