import { useCallback, useEffect, useRef, useState } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useAuth, atLeast } from "../auth";
import { api } from "../api/client";
import { clearUserStorage } from "../userStorage";
import { HealthDot } from "./HealthDot";
import { ThemeSelect } from "./ThemeSelect";
import { AgentDrawer } from "./AgentDrawer";
import { CommandPalette, usePaletteShortcut } from "./CommandPalette";
import { BrandMark, Icon } from "./icons";
import { SETTINGS_MIN } from "./nav";
import { useInventoryActivation } from "../inventory/InventoryGate";
import { useWorkspace, WORKSPACE_ROUTE } from "../workspace/WorkspaceContext";
import { useAiDrawer, type AiDrawerApi } from "../ai/drawer";

/** The search renders only on the workspace route. */
function Search() {
  const workspace = useWorkspace();
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const show = useCallback(() => setOpen(true), []);
  usePaletteShortcut(show);
  if (!workspace || pathname !== WORKSPACE_ROUTE) return null;

  return (
    <>
      <button type="button" className="searchbtn" onClick={show}>
        <Icon name="search" />
        <span className="searchbtn-text">Search</span>
      </button>
      {open && <CommandPalette onClose={() => setOpen(false)} />}
    </>
  );
}

/** The button exists only when the agent is enabled and has credentials.
 *
 *  The app shell's `AiDrawerProvider` (ai/drawer.tsx) holds the drawer's
 *  open state and conversation, and the pages open conversations there too. */
function HstAi() {
  // AppShell renders the top bar inside its AiDrawerProvider, always
  return <HstAiEntry drawer={useAiDrawer()!} />;
}

function HstAiEntry({ drawer }: { drawer: AiDrawerApi }) {
  const { open, setOpen } = drawer;
  const close = useCallback(() => setOpen(false), [setOpen]);
  if (!drawer.ready) return null;

  return (
    <>
      <button
        type="button"
        className="aibtn"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        HST AI
      </button>
      <AgentDrawer
        open={open}
        onClose={close}
        conversationId={drawer.conversationId}
        onConversation={drawer.setConversation}
      />
    </>
  );
}

export function TopBar() {
  const inventory = useInventoryActivation();
  const { user } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [menuOpen, setMenuOpen] = useState(false);
  const menu = useRef<HTMLDivElement | null>(null);
  const menuButton = useRef<HTMLButtonElement | null>(null);

  // The user menu is a disclosure: Escape closes it and gives the focus back
  // to its button, and a click outside it closes it.
  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      setMenuOpen(false);
      menuButton.current?.focus();
    };
    const onPointer = (e: PointerEvent) => {
      if (e.target instanceof Node && !menu.current?.contains(e.target)) setMenuOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onPointer);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("pointerdown", onPointer);
    };
  }, [menuOpen]);

  async function handleLogout() {
    setMenuOpen(false);
    try {
      await api("/logout", { method: "POST" });
    } catch {
      // the local state is cleared also when the POST fails
    } finally {
      queryClient.clear();
      queryClient.setQueryData(["me"], null);
      clearUserStorage();
      navigate("/login");
    }
  }

  return (
    <header className="app-topbar">
      <Link to={WORKSPACE_ROUTE} className="brand" aria-label="Back to the workspace">
        <BrandMark />
        <b>HST</b>
        <span>Flow Desk</span>
      </Link>
      {user && inventory.data?.activation_state === "active" && inventory.data.resolver_version === 2 && (
        <nav className="segs workspace-switcher" aria-label="Workspaces">
          <NavLink to={WORKSPACE_ROUTE} end className={({ isActive }) => isActive ? "on" : ""}>
            Analysis
          </NavLink>
          <NavLink to="/inventory" className={({ isActive }) => isActive ? "on" : ""}>
            Inventory
          </NavLink>
          <NavLink to="/applications" className={({ isActive }) => isActive ? "on" : ""}>
            Applications
          </NavLink>
        </nav>
      )}
      {user && <Search />}
      <div className="right">
        {user && <HealthDot />}
        {user && <HstAi />}
        {user && atLeast(user.role, SETTINGS_MIN) && (
          <NavLink
            to="/settings"
            className={({ isActive }) => "gearbtn" + (isActive ? " on" : "")}
            aria-label="Settings"
            title="Settings"
          >
            <Icon name="settings" size={17} />
          </NavLink>
        )}
        {user && (
          <div className="usermenu" ref={menu}>
            <button
              type="button"
              className="usermenu-btn"
              ref={menuButton}
              aria-expanded={menuOpen}
              aria-controls="usermenu-panel"
              onClick={() => setMenuOpen((open) => !open)}
            >
              <span className="avatar" aria-hidden="true">
                {user.username.slice(0, 2).toUpperCase()}
              </span>
              {user.username}
              <Icon name="chevron-down" size={14} />
            </button>
            {menuOpen && (
              <div className="usermenu-dropdown" id="usermenu-panel">
                <ThemeSelect />
                <ul className="usermenu-list">
                  <li>
                    <Link to="/settings/tokens" onClick={() => setMenuOpen(false)}>
                      Access tokens
                    </Link>
                  </li>
                  <li>
                    <a href="/api/docs" target="_blank" rel="noopener">
                      API documentation
                    </a>
                  </li>
                  <li>
                    <button type="button" onClick={handleLogout}>
                      Log out
                    </button>
                  </li>
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  );
}
