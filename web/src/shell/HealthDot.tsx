/**
 * The dot shows the state of `GET /api/health`.
 */

import type { Health } from "../api/types";
import { useHealth } from "./useHealth";

type Status = "checking" | "ok" | "part" | "err";

function computeStatus(data: Health | undefined, isError: boolean): Status {
  if (isError) return "err";
  if (!data) return "checking";
  return data.path && data.neo4j && data.postgres ? "ok" : "part";
}

const LABEL: Record<Status, string> = {
  checking: "checking",
  ok: "connected",
  part: "degraded",
  err: "offline",
};

export function HealthDot() {
  const { data, isError } = useHealth();
  const status = computeStatus(data, isError);
  const label = LABEL[status];

  return (
    // role="status" takes its accessible name from aria-label only
    <span className="conn" role="status" aria-label={label}>
      <span className={status === "checking" ? "dot" : `dot ${status}`} />
      <span>{label}</span>
    </span>
  );
}
