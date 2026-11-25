import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Navigate, useLocation } from "react-router";
import { inventoryApi } from "../api/inventory";
import { useAuth } from "../auth";
import { inventoryKeys } from "./queryKeys";
import "./inventory.css";

export function useInventoryActivation() {
  const { user } = useAuth();
  return useQuery({
    queryKey: inventoryKeys.state(),
    queryFn: inventoryApi.state,
    enabled: Boolean(user),
    retry: false,
    staleTime: 10_000,
  });
}

export function InventoryGate({ children }: { children: ReactNode }) {
  const state = useInventoryActivation();
  if (state.isPending) return <div className="ops-page inv-page"><p className="hint" role="status">Loading inventory status</p></div>;
  if (state.isError) {
    return <div className="ops-page inv-page">
      <section className="banner err" role="alert">
        <p>Inventory status not available</p>
        <div><button type="button" className="secondary" onClick={() => void state.refetch()}>Retry</button></div>
      </section>
    </div>;
  }
  if (state.data?.activation_state !== "active" || state.data.resolver_version !== 2) {
    return <div className="ops-page inv-page">
      <section className="editorcard inv-card">
        <h1>Inventory not activated</h1>
        <p className="hint">Activation state: {state.data?.activation_state ?? "unknown"}</p>
        <div><button type="button" className="secondary" onClick={() => void state.refetch()}>Refresh status</button></div>
      </section>
    </div>;
  }
  return <>
    {state.data.inventory_sync_pending && <div className="banner warn inv-gate-note" role="status">
      <p>Inventory publication pending</p>
    </div>}
    {children}
  </>;
}

export function InventoryRedirect({ to, children }: { to: string; children: ReactNode }) {
  const state = useInventoryActivation();
  const location = useLocation();
  if (state.data?.activation_state !== "active" || state.data.resolver_version !== 2) return children;
  const [path, search = ""] = to.split("?");
  const params = new URLSearchParams(location.search);
  new URLSearchParams(search).forEach((value, key) => params.set(key, value));
  return <Navigate to={{ pathname: path, search: params.toString() }} replace />;
}
