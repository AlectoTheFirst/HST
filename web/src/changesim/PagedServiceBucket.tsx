import { useState } from "react";
import type { ServiceImpactBucket } from "./assessImpact";
import { BucketSection } from "./Buckets";

type BucketPage = ServiceImpactBucket & {
  offset_decimal?: string;
  next_offset_decimal?: string | null;
};
export type LoadBucket = (name: string, offset: string) => Promise<BucketPage>;

export function PagedServiceBucket({ title, name, bucket, load }: {
  title: string; name: string; bucket: BucketPage; load?: LoadBucket;
}) {
  const [page, setPage] = useState(bucket);
  const [previous, setPrevious] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function navigate(offset: string, history: string[]) {
    if (!load || busy) return;
    setBusy(true); setError("");
    try {
      setPage(await load(name, offset));
      setPrevious(history);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "result page not loaded");
    } finally { setBusy(false); }
  }

  return <div>
    <BucketSection title={title} bucket={page} render={(cidr) => cidr} />
    {load && (page.next_offset_decimal != null || previous.length > 0) && <nav aria-label={`${title} pages`}>
      <button type="button" disabled={busy || previous.length === 0}
        onClick={() => void navigate(previous[previous.length - 1], previous.slice(0, -1))}>Previous</button>
      <button type="button" disabled={busy || page.next_offset_decimal == null}
        onClick={() => page.next_offset_decimal != null && void navigate(
          page.next_offset_decimal, [...previous.slice(-999), page.offset_decimal ?? "0"],
        )}>Next</button>
    </nav>}
    {busy && <p role="status">Loading result page</p>}
    {error && <p role="alert">{error}</p>}
  </div>;
}
