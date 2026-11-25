import { Outlet, useLocation } from "react-router";
import { TopBar } from "./TopBar";
import { SideRail } from "./SideRail";
import { WorkspaceProvider } from "../workspace/WorkspaceContext";
import { AiContextProvider } from "../ai/context";
import { AiDrawerProvider } from "../ai/drawer";
import { useAuth } from "../auth";
import { useThemeSync } from "./useThemeSync";
import { DeviceNamesProvider } from "./deviceNames";

/** The rail shows on the workspace route only. */
const RAIL_ROUTES = new Set(["/"]);

export function AppShell() {
  const { pathname } = useLocation();
  const withRail = RAIL_ROUTES.has(pathname);
  useThemeSync(useAuth().user);

  return (
    <DeviceNamesProvider>
      <WorkspaceProvider>
        <AiContextProvider>
          {/* the drawer's state: the top bar shows it, and pages open conversations in it */}
          <AiDrawerProvider inUrl>
            {/* the first stop of the Tab order: past the top bar and the rail */}
            <a className="skip-link" href="#main-content">
              Skip to content
            </a>
            <TopBar />
            <div className="shell-main">
              <div className={withRail ? "shell-body with-rail" : "shell-body"}>
                {withRail && <SideRail />}
                <main className="shell-content" id="main-content" tabIndex={-1}>
                  <Outlet />
                </main>
              </div>
            </div>
          </AiDrawerProvider>
        </AiContextProvider>
      </WorkspaceProvider>
    </DeviceNamesProvider>
  );
}
