import { Link, NavLink, Outlet, useLocation } from "react-router";
import { useAuth } from "../auth";
import "./inventory.css";
import { Suspense } from "react";

const PROFILES = "/inventory/connections/profiles";

/** Inventory uses the settings shell: a section list beside the routed page. */
export function InventoryLayout() {
  const { user, loading } = useAuth();
  const { pathname } = useLocation();
  if (loading) return <div className="ops-page inv-page"><p className="hint" role="status">Loading inventory access</p></div>;
  if (!user?.permissions.includes("graph.read")) {
    return <div className="ops-page inv-page"><p className="banner err" role="alert">No graph.read permission</p></div>;
  }
  const can = (permission: string) => user.permissions.includes(permission);
  const item = (active: boolean) => "rail-item q" + (active ? " on" : "");
  return (
    <div className="settings-layout inv-layout">
      <nav className="settings-nav" aria-label="Inventory">
        <Link to="/" className="rail-item q settings-back">Back to workspace</Link>
        <div className="eyebrow">Inventory</div>
        <NavLink to="/inventory/devices" className={({ isActive }) => item(isActive)}>Devices</NavLink>
        <NavLink to="/inventory/sites" className={({ isActive }) => item(isActive)}>Sites</NavLink>
        <NavLink to="/inventory/routing-groups" className={({ isActive }) => item(isActive)}>Routing groups</NavLink>
        {can("runs.manage") && (
          <NavLink to="/inventory/connections" className={() => item(pathname.startsWith("/inventory/connections") && !pathname.startsWith(PROFILES))}>
            Connections
          </NavLink>
        )}
        {can("sources.write") && <NavLink to={PROFILES} className={({ isActive }) => item(isActive)}>Profiles and credentials</NavLink>}
      </nav>
      <div className="settings-section">
        <Suspense fallback={<p className="hint">Loading</p>}>
          <Outlet />
        </Suspense>
      </div>
    </div>
  );
}
