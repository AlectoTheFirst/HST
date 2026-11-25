import { lazy } from "react";
import { Routes, Route, Navigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api/client";
import type { SetupStatus } from "./api/types";
import { RequireRole, atLeast, useAuth } from "./auth";
import Setup from "./pages/Setup";
import { AppShell } from "./shell/AppShell";
import Login from "./pages/Login";
import { Workspace } from "./workspace/Workspace";
import { SettingsLayout } from "./settings/SettingsLayout";
import { InventoryGate, InventoryRedirect } from "./inventory/InventoryGate";
import { InventoryLayout } from "./inventory/InventoryLayout";

// The settings and inventory pages load on first visit.
const RunsPage = lazy(() => import("./settings/RunsPage"));
const GroupsPage = lazy(() => import("./settings/GroupsPage"));
const OrchestratorsPage = lazy(() => import("./settings/OrchestratorsPage"));
const SitesPage = lazy(() => import("./settings/SitesPage"));
const DevicesPage = lazy(() => import("./settings/DevicesPage"));
const UsersPage = lazy(() => import("./settings/UsersPage"));
const AiSettingsPage = lazy(() => import("./settings/AiSettingsPage"));
const AuthSettingsPage = lazy(() => import("./settings/AuthSettingsPage"));
const LifecyclePage = lazy(() => import("./settings/LifecyclePage"));
const AccessTokensPage = lazy(() => import("./settings/AccessTokensPage"));
const InventoryDevicesPage = lazy(() =>
  import("./inventory/devices/DevicesPage").then((m) => ({ default: m.InventoryDevicesPage })),
);
const InventorySitesPage = lazy(() =>
  import("./inventory/sites/SitesPage").then((m) => ({ default: m.InventorySitesPage })),
);
const InventoryRoutingGroupsPage = lazy(() =>
  import("./inventory/routing/RoutingGroupsPage").then((m) => ({ default: m.InventoryRoutingGroupsPage })),
);
const ConnectionsPage = lazy(() =>
  import("./inventory/connections/ConnectionsPage").then((m) => ({ default: m.ConnectionsPage })),
);
const ConnectionDetailPage = lazy(() =>
  import("./inventory/connections/ConnectionDetailPage").then((m) => ({ default: m.ConnectionDetailPage })),
);
const ProfilesPage = lazy(() =>
  import("./inventory/profiles/ProfilesPage").then((m) => ({ default: m.ProfilesPage })),
);

/** `/settings` opens the first section the role may open: Runs from operator
 *  up, Access tokens for a viewer. */
function SettingsIndex() {
  const { user } = useAuth();
  return <Navigate to={user && atLeast(user.role, "operator") ? "runs" : "tokens"} replace />;
}

export default function App() {
  // With `retry: false`, an unreachable backend falls through to the normal routes.
  const { data: setup, isLoading } = useQuery<SetupStatus>({
    queryKey: ["setup"],
    queryFn: () => api<SetupStatus>("/setup"),
    retry: false,
    staleTime: Infinity,
  });

  if (isLoading) return null;

  if (setup?.required) {
    return (
      <Routes>
        <Route
          path="*"
          element={<Setup minPasswordLength={setup.min_password_length} />}
        />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<AppShell />}>
        <Route
          path="/"
          element={
            <RequireRole min="viewer">
              <Workspace />
            </RequireRole>
          }
        />
        <Route path="/inventory" element={
          <RequireRole min="viewer"><InventoryGate><InventoryLayout /></InventoryGate></RequireRole>
        }>
          <Route index element={<Navigate to="devices" replace />} />
          <Route path="devices" element={<InventoryDevicesPage />} />
          <Route path="devices/:id" element={<InventoryDevicesPage />} />
          <Route path="sites" element={<InventorySitesPage />} />
          <Route path="routing-groups" element={<InventoryRoutingGroupsPage />} />
          <Route path="connections" element={<RequireRole min="operator"><ConnectionsPage /></RequireRole>} />
          <Route path="connections/profiles" element={<RequireRole min="admin"><ProfilesPage /></RequireRole>} />
          <Route path="connections/:id" element={<RequireRole min="operator"><ConnectionDetailPage /></RequireRole>} />
        </Route>
        {/* The outer guard is the lowest section floor, the viewer's Access tokens. */}
        <Route
          path="/settings"
          element={
            <RequireRole min="viewer">
              <SettingsLayout />
            </RequireRole>
          }
        >
          <Route index element={<SettingsIndex />} />
          <Route path="sources" element={<InventoryRedirect to="/inventory/connections"><Navigate to="/settings/groups" replace /></InventoryRedirect>} />
          <Route
            path="runs"
            element={
              <RequireRole min="operator">
                <RunsPage />
              </RequireRole>
            }
          />
          <Route
            path="orchestrators"
            element={
              <RequireRole min="operator">
                <InventoryRedirect to="/inventory/connections?kind=controller"><OrchestratorsPage /></InventoryRedirect>
              </RequireRole>
            }
          />
          <Route
            path="groups"
            element={
              <RequireRole min="operator">
                <InventoryRedirect to="/inventory/connections?kind=direct"><GroupsPage /></InventoryRedirect>
              </RequireRole>
            }
          />
          <Route
            path="devices"
            element={
              <RequireRole min="operator">
                <InventoryRedirect to="/inventory/devices"><DevicesPage /></InventoryRedirect>
              </RequireRole>
            }
          />
          <Route
            path="sites"
            element={
              <RequireRole min="operator">
                <InventoryRedirect to="/inventory/sites"><SitesPage /></InventoryRedirect>
              </RequireRole>
            }
          />
          <Route
            path="users"
            element={
              <RequireRole min="admin">
                <UsersPage />
              </RequireRole>
            }
          />
          <Route
            path="ai"
            element={
              <RequireRole min="admin">
                <AiSettingsPage />
              </RequireRole>
            }
          />
          <Route
            path="auth"
            element={
              <RequireRole min="admin">
                <AuthSettingsPage />
              </RequireRole>
            }
          />
          <Route
            path="lifecycle"
            element={
              <RequireRole min="admin">
                <LifecyclePage />
              </RequireRole>
            }
          />
          <Route
            path="tokens"
            element={
              <RequireRole min="viewer">
                <AccessTokensPage />
              </RequireRole>
            }
          />
        </Route>
      </Route>
      {/* The server answers every non-API path with index.html. */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
