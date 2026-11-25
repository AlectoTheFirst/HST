import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { EvidenceValue } from "./AnalysisResult";
import { Field } from "./RequirementComposer";
import type { Assessment, AssessmentDetail } from "./types";

export function RevisionHistory({ assessment }: { assessment: Assessment }) {
  const [revision, setRevision] = useState(Math.max(1, assessment.revision - 1));
  const valid = Number.isInteger(revision) && revision > 0 && revision <= assessment.revision;
  const previous = useQuery({
    queryKey: ["assessment-revision", assessment.id, revision],
    queryFn: () =>
      api<AssessmentDetail>(
        `/assessments/${encodeURIComponent(assessment.id)}?revision=${revision}`,
      ),
    enabled: valid,
  });
  const older = previous.data?.assessment;
  return (
    <section>
      <h3>Compare revisions</h3>
      <Field
        label="Compare revision"
        type="number"
        value={revision}
        onChange={(v) => setRevision(Number(v))}
      />
      {!valid && <p role="alert">Revision from 1 to {assessment.revision}</p>}
      {previous.isLoading && <p role="status">Loading revision</p>}
      {previous.isError && <p role="alert">Could not load the selected revision</p>}
      {older && (
        <div className="assessment-fields">
          <section>
            <h3>Revision {older.revision}</h3>
            <p>{older.title}</p>
            <EvidenceValue value={older.definition} />
          </section>
          <section>
            <h3>Current revision {assessment.revision}</h3>
            <p>{assessment.title}</p>
            <EvidenceValue value={assessment.definition} />
          </section>
        </div>
      )}
    </section>
  );
}
