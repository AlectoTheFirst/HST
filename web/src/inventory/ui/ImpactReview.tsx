import { useEffect, useRef, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { ApiError } from "../../api/client";
import { inventoryApi, type PreviewRequest, type PreviewResponse } from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";
import { useAction } from "../shared";
import { ErrorNotice } from "./ErrorNotice";
import { MEMBER_KIND, OPERATION_LABEL, flatten, formatValue, humanize } from "./format";
import { Facts, Modal, Stat } from "./Page";

/** The codes of an apply refused for a stale or expired preview. */
const STALE = new Set(["inventory_changed", "stale_revision", "preview_expired"]);
const SHOWN_MEMBERS = 10;

/** The preview stays in component state, out of the mutation cache. */
export function ImpactReview({ request, onDone, onCancel }: { request: PreviewRequest; onDone: () => void; onCancel: () => void }) {
  const action = useAction();
  const [preview, setPreview] = useState<PreviewResponse | null>(null);
  const [key, setKey] = useState(() => crypto.randomUUID());
  const [notice, setNotice] = useState("");
  const title = OPERATION_LABEL[request.operation] ?? humanize(request.operation);
  const calculate = (reason = "") => action.run(() => inventoryApi.preview(request), result => {
    setPreview(result); setKey(crypto.randomUUID()); setNotice(reason);
  });
  // One preview per dialog, also under StrictMode's double effect run.
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void calculate();
  });
  async function apply() {
    if (!preview) return;
    if (Date.parse(preview.expires_at) <= Date.now()) {
      await calculate("Preview expired");
      return;
    }
    let stale = false;
    await action.run(async () => {
      try { return await inventoryApi.apply({ token: preview.token, idempotency_key: key }); }
      catch (err) { stale = err instanceof ApiError && (STALE.has(err.code ?? "") || err.status === 409); throw err; }
    }, onDone);
    if (stale) await calculate("Inventory changed after the preview");
  }
  const busy = action.pending && !!preview;
  return (
    <Modal label={`Confirm ${title.toLowerCase()}`} title={title} wide locked={busy} onClose={onCancel} footer={<>
      <button type="button" className="secondary" disabled={busy} onClick={onCancel}>Cancel</button>
      <button type="button" className="primary" disabled={!preview || action.pending} onClick={() => void apply()}>
        {busy ? "Applying" : "Apply"}
      </button>
    </>}>
      {!preview && !action.error && <p className="hint" role="status">Calculating impact</p>}
      {notice && <div className="banner warn" role="status"><p>{notice}</p></div>}
      <ErrorNotice error={action.error} retry={preview ? undefined : () => void calculate()} />
      {preview && <ImpactSummary key={preview.token} preview={preview} />}
    </Modal>
  );
}

function ImpactSummary({ preview }: { preview: PreviewResponse }) {
  const [allMembers, setAllMembers] = useState(false);
  const impacts = useInfiniteQuery({
    queryKey: inventoryKeys.previews.impact(preview.token),
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => inventoryApi.previewImpact(preview.token, { cursor: pageParam, limit: 100 }),
    getNextPageParam: last => last.next_cursor ?? undefined,
    retry: false,
  });
  const items = impacts.data?.pages.flatMap(p => p.items) ?? [];
  const total = impacts.data?.pages[0]?.total ?? 0;
  const changes = flatten(preview.changes);
  const members = allMembers ? preview.members : preview.members.slice(0, SHOWN_MEMBERS);
  return (
    <>
      <div className="inv-stats">
        <Stat label="Selected records" value={preview.member_count.toLocaleString()} />
        <Stat label="Affected targets" value={preview.affected_target_count.toLocaleString()} />
        <Stat label="Affected devices" value={preview.affected_device_count.toLocaleString()} />
      </div>
      {preview.warnings.map(warning => <div className="banner warn" role="status" key={warning}><p>{warning}</p></div>)}

      {changes.length > 0 && (
        <section className="inv-review-section">
          <h3 className="eyebrow">Changes</h3>
          <Facts rows={changes.map(([path, value]) => [humanize(path), formatValue(value)])} />
        </section>
      )}

      <section className="inv-review-section">
        <h3 className="eyebrow">Selected records</h3>
        <ul className="inv-list">
          {members.map(member => (
            <li key={`${member.kind}-${member.id}`}>
              <span className="inv-kind">{MEMBER_KIND[member.kind] ?? member.kind}</span> {member.label || member.id}
            </li>
          ))}
        </ul>
        {preview.members.length > SHOWN_MEMBERS && !allMembers && (
          <div><button type="button" className="secondary" onClick={() => setAllMembers(true)}>Show all {preview.members.length.toLocaleString()}</button></div>
        )}
      </section>

      <details className="inv-review-section">
        <summary>Affected records{impacts.data ? `: ${total.toLocaleString()}` : ""}</summary>
        <ErrorNotice error={impacts.error} retry={() => void impacts.refetch()} />
        {impacts.isPending && <p className="hint">Loading affected records</p>}
        {impacts.data && items.length === 0 && <p className="hint">No other affected records</p>}
        {items.length > 0 && (
          <div className="results inv-table">
            <table>
              <thead><tr><th>Kind</th><th>Record</th><th>Effect</th></tr></thead>
              <tbody>
                {items.map((item, index) => (
                  <tr key={`${item.kind}-${item.entity_id}-${index}`}>
                    <td>{MEMBER_KIND[item.kind] ?? item.kind}</td>
                    <td className="mono">{item.entity_id}</td>
                    <td>{flatten(item.detail).map(([path, value]) => <div key={path}><span className="inv-muted">{humanize(path)}:</span> {formatValue(value)}</div>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {impacts.hasNextPage && (
          <div><button type="button" className="secondary" disabled={impacts.isFetchingNextPage} onClick={() => void impacts.fetchNextPage()}>Load more affected records</button></div>
        )}
      </details>
    </>
  );
}
