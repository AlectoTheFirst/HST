/**
 * `staleTime` equals the poll interval.
 */

import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Health } from "../api/types";

const HEALTH_POLL_MS = 30_000;

/** `enabled` false reads what the poll holds without polling itself. */
export function useHealth(enabled = true) {
  return useQuery<Health>({
    queryKey: ["health"],
    queryFn: () => api<Health>("/health"),
    refetchInterval: HEALTH_POLL_MS,
    staleTime: HEALTH_POLL_MS,
    retry: false,
    enabled,
  });
}
