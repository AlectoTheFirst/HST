/**
 * React Query keys of the inventory.
 */

import type { QueryClient } from "@tanstack/react-query";
import type { DeviceListQuery } from "../api/inventory";

const ROOT = "inventory" as const;

/** The estate drawing of the network map: sites, their coordinates and the links between them. */
export const SITES_GRAPH_KEY = ["sites-graph"] as const;

export const inventoryKeys = {
  all: [ROOT] as const,
  state: () => [ROOT, "state"] as const,
  fieldMetadata: () => [ROOT, "field-metadata"] as const,

  devices: {
    all: [ROOT, "devices"] as const,
    list: (params: DeviceListQuery) => [ROOT, "devices", "list", params] as const,
    /** Every page of the devices placed at one site, not one page of them. */
    atSite: (siteId: string) => [ROOT, "devices", "at-site", siteId] as const,
    detail: (id: string) => [ROOT, "devices", "detail", id] as const,
    routing: (id: string, snapshotKey?: string) =>
      [ROOT, "devices", "routing", id, snapshotKey ?? "current"] as const,
    history: (id: string) => [ROOT, "devices", "history", id] as const,
  },

  sites: {
    all: [ROOT, "sites"] as const,
    list: () => [ROOT, "sites", "list"] as const,
    search: (params: object) => [ROOT, "sites", "search", params] as const,
    detail: (id: string) => [ROOT, "sites", "detail", id] as const,
  },

  locations: {
    all: [ROOT, "locations"] as const,
    list: (connectionId?: string) => [ROOT, "locations", "list", connectionId ?? "all"] as const,
    search: (params: object) => [ROOT, "locations", "search", params] as const,
  },

  connections: {
    all: [ROOT, "connections"] as const,
    list: (params: { kind?: string; collector_type?: string }) => [ROOT, "connections", "list", params] as const,
    detail: (id: string) => [ROOT, "connections", "detail", id] as const,
  },

  targets: {
    all: [ROOT, "targets"] as const,
    list: (connectionId?: string) => [ROOT, "targets", "list", connectionId ?? "all"] as const,
    detail: (id: string) => [ROOT, "targets", "detail", id] as const,
    effective: (id: string) => [ROOT, "targets", "effective", id] as const,
  },

  profiles: {
    all: [ROOT, "profiles"] as const,
    list: (collectorType?: string) => [ROOT, "profiles", "list", collectorType ?? "all"] as const,
    detail: (id: string) => [ROOT, "profiles", "detail", id] as const,
    impact: (id: string) => [ROOT, "profiles", "impact", id] as const,
  },

  credentials: {
    all: [ROOT, "credentials"] as const,
    list: () => [ROOT, "credentials", "list"] as const,
    detail: (id: string) => [ROOT, "credentials", "detail", id] as const,
  },

  views: {
    all: [ROOT, "views"] as const,
    list: () => [ROOT, "views", "list"] as const,
    detail: (id: string) => [ROOT, "views", "detail", id] as const,
  },

  routingGroups: {
    all: [ROOT, "routing-groups"] as const,
    list: () => [ROOT, "routing-groups", "list"] as const,
    detail: (id: string) => [ROOT, "routing-groups", "detail", id] as const,
  },

  previews: {
    impact: (token: string) => [ROOT, "previews", "impact", token] as const,
  },
};

export type InventoryWriteKind =
  | "placement"
  | "lifecycle"
  | "collect"
  | "connection"
  | "target"
  | "profile"
  | "credential"
  | "site"
  | "location"
  | "view"
  | "routing-group"
  | "apply";

export interface InventoryWriteScope {
  /** The device the write was about, when there is one. */
  deviceId?: string;
  /** The device ids a bulk apply reported, when known. */
  deviceIds?: string[];
  profileId?: string;
  connectionId?: string;
  targetId?: string;
  siteId?: string;
}

/** The dependent keys for a write kind, in the order they are invalidated. */
export function dependentKeys(kind: InventoryWriteKind, scope: InventoryWriteScope = {}): readonly (readonly unknown[])[] {
  const keys: (readonly unknown[])[] = [inventoryKeys.state()];
  const deviceKeys = () => {
    keys.push(inventoryKeys.devices.all);
    for (const id of [scope.deviceId, ...(scope.deviceIds ?? [])]) {
      if (id) keys.push(inventoryKeys.devices.detail(id), inventoryKeys.devices.history(id));
    }
  };
  switch (kind) {
    case "placement":
      deviceKeys();
      keys.push(inventoryKeys.sites.all, inventoryKeys.locations.all, SITES_GRAPH_KEY);
      break;
    case "lifecycle":
      deviceKeys();
      keys.push(inventoryKeys.sites.all);
      break;
    case "collect":
      deviceKeys();
      keys.push(inventoryKeys.targets.all, inventoryKeys.connections.all);
      break;
    case "connection":
      keys.push(inventoryKeys.connections.all, inventoryKeys.targets.all, inventoryKeys.devices.all, inventoryKeys.locations.all);
      if (scope.connectionId) keys.push(inventoryKeys.connections.detail(scope.connectionId));
      break;
    case "target":
      keys.push(inventoryKeys.targets.all, inventoryKeys.connections.all, inventoryKeys.devices.all);
      if (scope.targetId) keys.push(inventoryKeys.targets.effective(scope.targetId));
      if (scope.profileId) keys.push(inventoryKeys.profiles.impact(scope.profileId));
      break;
    case "profile":
      keys.push(inventoryKeys.profiles.all, inventoryKeys.targets.all, inventoryKeys.connections.all, inventoryKeys.devices.all);
      if (scope.profileId) keys.push(inventoryKeys.profiles.impact(scope.profileId));
      break;
    case "credential":
      keys.push(inventoryKeys.credentials.all, inventoryKeys.profiles.all, inventoryKeys.targets.all);
      break;
    case "site":
      keys.push(inventoryKeys.sites.all, inventoryKeys.locations.all, inventoryKeys.devices.all, inventoryKeys.targets.all, SITES_GRAPH_KEY);
      if (scope.siteId) keys.push(inventoryKeys.sites.detail(scope.siteId));
      break;
    case "location":
      keys.push(inventoryKeys.locations.all, inventoryKeys.sites.all, inventoryKeys.devices.all, SITES_GRAPH_KEY);
      break;
    case "view":
      keys.push(inventoryKeys.views.all);
      break;
    case "routing-group":
      keys.push(inventoryKeys.routingGroups.all);
      for (const id of [scope.deviceId, ...(scope.deviceIds ?? [])]) {
        if (id) keys.push(inventoryKeys.devices.routing(id));
      }
      break;
    case "apply":
      keys.push(inventoryKeys.all, SITES_GRAPH_KEY);
      break;
  }
  return keys;
}

/** Invalidate everything a successful write can have changed. Returns when the
 *  invalidations are issued. */
export async function invalidateAfterInventoryWrite(
  client: QueryClient,
  kind: InventoryWriteKind,
  scope: InventoryWriteScope = {},
): Promise<void> {
  await Promise.all(dependentKeys(kind, scope).map((queryKey) => client.invalidateQueries({ queryKey })));
}
