import { Link } from "react-router";

/**
 * `RequireRole` (../auth) renders this page for a role below the route's role.
 */
export function Forbidden() {
  return (
    <div className="forbidden-shell">
      <div className="forbidden-card" role="alert">
        <b>Forbidden</b>
        <Link className="forbidden-link" to="/">
          Back to Trace
        </Link>
      </div>
    </div>
  );
}
