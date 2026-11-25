import type { CollectionProgress } from "../api/types";
import { useEffect, useState } from "react";

export function CollectionProgressView({ progress }: { progress: CollectionProgress }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 5000);
    return () => window.clearInterval(timer);
  }, []);
  const stale = now - progress.updated_at_ms > 30_000;
  const eta = progress.phase_eta_s;
  const etaText = eta == null ? "Estimating remaining time" : eta < 60 ? `About ${eta}s remaining` : `About ${Math.ceil(eta / 60)} min remaining`;
  return <div role="status" aria-label={`Collection progress for ${progress.source}`}>
    <div>{progress.source}{progress.enterprise ? `: enterprise ${progress.enterprise_index} of ${progress.enterprise_total} (${progress.enterprise})` : ""}</div>
    {progress.state === "collected" ? <div>Preparing snapshot</div> : progress.state === "failed" ? <div>Collection failed</div> : <>
      <div>{progress.phase}{progress.total != null ? `: ${progress.completed.toLocaleString()} of ${progress.total.toLocaleString()}` : ""}</div>
      <progress aria-label={progress.phase} max={Math.max(1, progress.total ?? 1)} value={progress.total == null ? undefined : progress.completed} />
      {progress.total != null && <div>{stale ? "Estimate paused" : `${etaText} in this phase`}</div>}
    </>}
    {!!progress.cache_hits && <div>{progress.cache_hits.toLocaleString()} cached responses reused</div>}
    {!!progress.reverse_queries_saved && <div>{progress.reverse_queries_saved.toLocaleString()} reverse-direction requests avoided</div>}
  </div>;
}
