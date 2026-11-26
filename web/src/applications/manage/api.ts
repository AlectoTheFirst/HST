import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ExecutionState } from "../../analysis/contracts";
import type { ApplicationRevision } from "../types";

/** An item of GET /business-applications: the latest revision with its review flag and counts. */
export interface CatalogEntry extends ApplicationRevision {
  review?: "open" | null;
  analyses?: number;
  connections?: number;
}

export interface ApplicationAnalysis {
  session_id: string;
  title: string;
  kind: string;
  session_revision: number;
  bound_revisions: number[];
  current_revision: number;
  stale: boolean;
  runs: Array<{ id: string; execution: ExecutionState }>;
}

export interface Review {
  id: string;
  application_id: string;
  state: "open" | "closed";
  reason: string;
  revision: number;
  opened_at: string;
  /** null on a flag that a saved revision opened */
  opened_by: number | null;
  /** the username of `opened_by`, or null */
  opened_by_name: string | null;
  closed_at: string | null;
  closed_by: number | null;
  /** the username of `closed_by`, or null */
  closed_by_name: string | null;
}

export const catalogKey = ["business-applications"] as const;
export const analysesKey = (id: string) => ["business-application-analyses", id] as const;
export const reviewKey = (id: string) => ["business-application-review", id] as const;

export function useCatalog() {
  return useQuery({
    queryKey: catalogKey,
    queryFn: () => api<{ applications: CatalogEntry[] }>("/business-applications"),
  });
}

export function useAnalyses(id: string) {
  return useQuery({
    queryKey: analysesKey(id),
    queryFn: () =>
      api<{ analyses: ApplicationAnalysis[] }>(
        `/business-applications/${encodeURIComponent(id)}/analyses`,
      ),
  });
}

export function useReview(id: string, enabled: boolean) {
  return useQuery({
    queryKey: reviewKey(id),
    queryFn: () =>
      api<{ current: Review | null; history: Review[] }>(
        `/business-applications/${encodeURIComponent(id)}/review`,
      ),
    enabled,
  });
}

export function openReview(id: string, reason: string) {
  return api<Review>(`/business-applications/${encodeURIComponent(id)}/review`, {
    method: "POST",
    body: { reason },
  });
}

export function closeReview(id: string) {
  return api<Review>(`/business-applications/${encodeURIComponent(id)}/review/close`, {
    method: "POST",
  });
}

export const REASON_MAX = 500;

/** The user of a review event: the username, "user 3" for a user without a
 *  username, or "automatic" for a flag without a user. */
export function byText(user: number | null, name: string | null = null): string {
  if (user == null) return "automatic";
  return name ?? `user ${user}`;
}

/** A local time as `YYYY-MM-DD HH:MM`. */
export function formatTime(value: string | null | undefined): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const two = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())} ${two(date.getHours())}:${two(date.getMinutes())}`;
}

/** The bound revision text of an analysis: "1, not 2" when it is bound to an older revision. */
export function boundText(analysis: ApplicationAnalysis): string {
  const older = analysis.bound_revisions.filter((item) => item !== analysis.current_revision);
  if (!analysis.stale || older.length === 0) return analysis.bound_revisions.join(", ");
  return `${older.join(", ")}, not ${analysis.current_revision}`;
}
