import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { analysesKey, catalogKey, closeReview, openReview, reviewKey } from "./api";

/** Opens or closes the review flags of applications and refreshes the catalog and each review. */
export function useReviewActions() {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function run(ids: string[], action: (id: string) => Promise<unknown>): Promise<boolean> {
    setBusy(true);
    setError("");
    try {
      await Promise.all(ids.map(action));
      return true;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Review not changed");
      return false;
    } finally {
      setBusy(false);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: catalogKey }),
        ...ids.flatMap((id) => [
          queryClient.invalidateQueries({ queryKey: reviewKey(id) }),
          queryClient.invalidateQueries({ queryKey: analysesKey(id) }),
        ]),
      ]);
    }
  }
  return {
    busy,
    error,
    flag: (ids: string[], reason: string) => run(ids, (id) => openReview(id, reason)),
    close: (ids: string[]) => run(ids, closeReview),
  };
}
