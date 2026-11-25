import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { inventoryApi } from "../api/inventory";
import type { QueuedRun, SourceTypesResponse } from "../api/types";
import { useAuth } from "../auth";
import { inventoryKeys, invalidateAfterInventoryWrite, type InventoryWriteKind } from "./queryKeys";

/** Inventory permissions by what they unlock. */
export function useCapabilities() {
  const { user } = useAuth();
  const has = (permission: string) => !!user?.permissions.includes(permission);
  return {
    /** Connection, target and collection internals. */
    read: has("runs.manage"),
    /** Connections, targets, profiles, credentials and routing groups. */
    write: has("sources.write"),
    sites: has("sites.write"),
    lifecycle: has("inventory.write"),
  };
}

export function useCatalog() {
  const { write } = useCapabilities();
  const metadata = useQuery({ queryKey: inventoryKeys.fieldMetadata(), queryFn: inventoryApi.fieldMetadata, enabled: write });
  const schemas = useQuery({ queryKey: ["source-types"], queryFn: () => api<SourceTypesResponse>("/source-types"), enabled: write });
  return { metadata, schemas };
}

// Keeps the mutation variables out of the React Query cache.
export function useAction(kind: InventoryWriteKind = "apply") {
  const client = useQueryClient();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [message, setMessage] = useState("");
  async function run<T>(action: () => Promise<T>, done?: (value: T) => void) {
    setPending(true); setError(null); setMessage("");
    try { const result = await action(); await invalidateAfterInventoryWrite(client, kind); done?.(result); return result; }
    catch (err) { setError(err); return undefined; }
    finally { setPending(false); }
  }
  const reset = () => { setError(null); setMessage(""); };
  return { pending, error, message, setMessage, run, reset };
}

/** A non-secret form draft in session storage, keyed by user. */
export function useInventoryDraft<T>(key: string, initial: T): [T, (next: T) => void, () => void] {
  const { user } = useAuth();
  const storageKey = `hst.inventory.draft:${user?.username ?? "anonymous"}:${key}`;
  const [value, setValue] = useState<T>(() => {
    try { const saved = sessionStorage.getItem(storageKey); if (saved) return JSON.parse(saved) as T; sessionStorage.setItem(storageKey, JSON.stringify(initial)); return initial; } catch { return initial; }
  });
  const update = (next: T) => {
    setValue(next);
    try { sessionStorage.setItem(storageKey, JSON.stringify(next)); } catch { /* Storage disabled: the draft stays in memory. */ }
  };
  const clear = () => {
    setValue(initial);
    try { sessionStorage.removeItem(storageKey); } catch { /* Storage disabled. */ }
  };
  return [value, update, clear];
}

export const deviceLink = (id: string) => `/inventory/devices/${encodeURIComponent(id)}`;
export const connectionLink = (id: string) => `/inventory/connections/${encodeURIComponent(id)}`;
/** A run row, or with RUN_EXECUTION=queue the queued job that will start it. */
export const collectConnection = (source: string) => api<{ id: number; status: string } | QueuedRun>("/runs", { method: "POST", body: { source } });
