import { useNavigate } from "react-router";
import { atLeast, useAuth } from "../../auth";
import { PageHeader } from "../../inventory/ui/Page";
import { ApplicationImport } from "../ApplicationImport";

export function ApplicationImportPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  return (
    <section className="ops-page inv-page apps-page" aria-label="Import">
      <PageHeader title="Import" />
      <ApplicationImport
        canEdit={!!user && atLeast(user.role, "operator")}
        onCommitted={(id) => navigate(`/applications/${encodeURIComponent(id)}`)}
      />
    </section>
  );
}
