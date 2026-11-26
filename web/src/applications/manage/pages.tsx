import { Navigate } from "react-router";
import { useAuth } from "../../auth";
import { ApplicationsListPage } from "./ApplicationsListPage";

export { ApplicationDetailPage } from "./ApplicationDetailPage";
export { ApplicationImportPage } from "./ApplicationImportPage";
export { ApplicationsListPage };

/** The Review section needs changes.write. */
export function ApplicationsReviewPage() {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user?.permissions.includes("changes.write")) return <Navigate to="/applications" replace />;
  return <ApplicationsListPage reviewOnly />;
}
