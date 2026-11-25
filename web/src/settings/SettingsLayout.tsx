/**
 * The settings home shows a role-filtered sub-nav beside the routed section.
 */

import { Link, NavLink, Outlet } from "react-router";
import { useAuth, atLeast } from "../auth";
import { SETTINGS_ITEMS } from "../shell/nav";
import { useInventoryActivation } from "../inventory/InventoryGate";
import { Suspense } from "react";

export function SettingsLayout() {
  const { user } = useAuth();
  const active = useInventoryActivation().data?.activation_state === "active";
  const moved = new Set(["/settings/groups", "/settings/devices", "/settings/sites", "/settings/orchestrators"]);
  const items = user ? SETTINGS_ITEMS.filter((item) =>
    atLeast(user.role, item.min) && !(active && moved.has(item.to))) : [];

  return (
    <div className="settings-layout">
      <nav className="settings-nav" aria-label="Settings sections">
        <Link to="/" className="rail-item q settings-back">
          Workspace
        </Link>
        <div className="eyebrow">Settings</div>
        {active && <Link to="/inventory/devices" className="rail-item q">Inventory</Link>}
        {items.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => "rail-item q" + (isActive ? " on" : "")}
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="settings-section">
        <Suspense fallback={<p className="hint">Loading</p>}>
          <Outlet />
        </Suspense>
      </div>
    </div>
  );
}
