import { Suspense } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router";
import { useAuth } from "../../auth";
import { useCatalog } from "./api";
import "../../inventory/inventory.css";
import "../applications.css";
import "./manage.css";

/** Business applications use the settings shell: a section list beside the routed page. */
export function ApplicationsLayout() {
  const { user } = useAuth();
  const canReview = !!user?.permissions.includes("changes.write");
  const { pathname } = useLocation();
  const catalog = useCatalog();
  const inList = !/^\/applications\/(review|import)(\/|$)/.test(pathname);
  const open = catalog.data?.applications.filter((item) => item.review === "open").length ?? 0;
  const item = ({ isActive }: { isActive: boolean }) => "rail-item q" + (isActive ? " on" : "");
  return (
    <div className="settings-layout inv-layout">
      <nav className="settings-nav" aria-label="Applications">
        <Link to="/" className="rail-item q settings-back">Back to workspace</Link>
        <div className="eyebrow">Applications</div>
        <Link to="/applications" className={item({ isActive: inList })} aria-current={inList ? "page" : undefined}>
          Applications
        </Link>
        {canReview && (
          <NavLink to="/applications/review" className={item}>
            Review {open > 0 && <span className="apps-count">{open}</span>}
          </NavLink>
        )}
        <NavLink to="/applications/import" className={item}>Import</NavLink>
      </nav>
      <div className="settings-section">
        <Suspense fallback={<p className="hint">Loading</p>}>
          <Outlet />
        </Suspense>
      </div>
    </div>
  );
}
