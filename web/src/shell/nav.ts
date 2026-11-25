/**
 * The settings sections behind the gear.
 *
 * `min` is the role floor below which a section is hidden.
 */

import type { Role } from "../api/types";

interface NavItem {
  to: string;
  label: string;
  min: Role;
}

export const SETTINGS_ITEMS: readonly NavItem[] = [
  { to: "/settings/runs", label: "Runs", min: "operator" },
  { to: "/settings/groups", label: "Groups", min: "operator" },
  { to: "/settings/devices", label: "Devices", min: "operator" },
  { to: "/settings/sites", label: "Sites", min: "operator" },
  { to: "/settings/orchestrators", label: "Orchestrators", min: "operator" },
  { to: "/settings/users", label: "Users", min: "admin" },
  { to: "/settings/ai", label: "AI agent", min: "admin" },
  { to: "/settings/auth", label: "Authentication", min: "admin" },
  { to: "/settings/lifecycle", label: "Lifecycle", min: "admin" },
  { to: "/settings/tokens", label: "Access tokens", min: "viewer" },
];

/** Role floor for the settings gear. A viewer's one section, Access tokens, is
 *  opened from the user menu. */
export const SETTINGS_MIN: Role = "operator";
