/**
 * The route table of a Device or VrfInstance, read from the side store for the
 * snapshot (GET /api/explore/routes): the same files a trace of this snapshot
 * reads. For a device, every VRF answers and each row names its own. An
 * address filter shows the routes that cover it, longest prefix first; the
 * server marks the rows at the longest prefix of each routing table.
 */

import { useEffect, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ApiError } from "../api/client";
import { exploreApi } from "../api/explore";

const PAGE = 50;

function useDebounced<T>(value: T, delay = 300): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return settled;
}

const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** A complete IPv4 or IPv6 address, as the server accepts it. */
export function isAddress(text: string): boolean {
  if (V4.test(text)) return true;
  if (!text.includes(":") || !/^[0-9a-fA-F:.]+$/.test(text)) return false;
  try {
    return new URL(`http://[${text}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

/** `complete` and `complete-empty` have no entry. */
const COVERAGE: Record<string, string> = {
  failed: "Route table read failed",
  partial: "Partial route table",
  missing: "Route table file missing",
  unsupported: "Route table not supported",
};

export function RoutesPanel({ uid, perVrf }: { uid: string; perVrf: boolean }) {
  const [address, setAddress] = useState("");
  const [prefix, setPrefix] = useState("");
  const [protocol, setProtocol] = useState("");
  const [offset, setOffset] = useState(0);
  const a = useDebounced(address.trim());
  const p = useDebounced(prefix.trim());
  const addressOk = a === "" || isAddress(a);
  const params = { uid, address: addressOk ? a || undefined : undefined, prefix: p || undefined, protocol: protocol || undefined, offset, limit: PAGE };
  const page = useQuery({
    queryKey: ["explore", "routes", params],
    queryFn: () => exploreApi.routes(params),
    placeholderData: keepPreviousData,
  });
  const d = page.data;
  // When a fresh page names another snapshot, the table starts again at the first page.
  const [run, setRun] = useState<{ uid: string; snapshot: number | null } | null>(null);
  const [runChanged, setRunChanged] = useState(false);
  const fresh = d && !page.isPlaceholderData && !page.isFetching ? (d.snapshot ?? null) : undefined;
  if (fresh !== undefined) {
    if (run === null || run.uid !== uid) {
      setRun({ uid, snapshot: fresh });
      if (runChanged) setRunChanged(false);
    } else if (run.snapshot !== fresh) {
      setRun({ uid, snapshot: fresh });
      setRunChanged(true);
      setOffset(0);
    }
  }
  // the rows of the previous request stay on screen, dimmed, while a new one runs
  const stale = page.isPlaceholderData;
  const refilter = (edit: () => void) => { edit(); setOffset(0); setRunChanged(false); };
  const turn = (to: number) => { setOffset(to); setRunChanged(false); };
  return (
    <section className="xr" aria-label="Routes">
      <h3 className="eyebrow">Routes</h3>
      <div className="xr-filters">
        <label className="xr-field"><span>Longest match for address</span>
          <input className="xb-input" value={address} placeholder="10.1.2.7" spellCheck={false}
            aria-invalid={!addressOk} onChange={(e) => refilter(() => setAddress(e.target.value))} />
        </label>
        <label className="xr-field"><span>Prefix contains</span>
          <input className="xb-input" value={prefix} placeholder="10.1." spellCheck={false}
            onChange={(e) => refilter(() => setPrefix(e.target.value))} />
        </label>
      </div>
      {!addressOk && <p className="hint">Not an IPv4 or IPv6 address</p>}
      {d && d.protocols.some((row) => row.protocol) && (
        <div className="xb-chips" role="group" aria-label="Filter by protocol">
          <button type="button" className={"xb-chip" + (protocol === "" ? " on" : "")} aria-pressed={protocol === ""} onClick={() => refilter(() => setProtocol(""))}>All</button>
          {d.protocols.filter((row) => row.protocol).map((row) => (
            <button key={row.protocol} type="button" className={"xb-chip" + (protocol === row.protocol ? " on" : "")}
              aria-pressed={protocol === row.protocol} onClick={() => refilter(() => setProtocol(row.protocol))}>
              {row.protocol} <span className="xb-count">{row.count.toLocaleString()}</span>
            </button>
          ))}
        </div>
      )}
      {(page.isPending || stale) && <p className="hint" role="status">Loading</p>}
      {runChanged && <p className="hint" role="status">Snapshot changed</p>}
      {page.isError && <div className="banner err"><div className="sub">{page.error instanceof ApiError ? page.error.message : "Request failed"}</div></div>}
      {d && !d.available && <p className="hint">No route table</p>}
      {d?.available && d.coverage && d.coverage in COVERAGE && (
        <div className="banner warn"><div className="sub">{COVERAGE[d.coverage]}</div></div>
      )}
      {d?.available && d.approximate && <p className="hint">Newest route table before this snapshot</p>}
      {d?.available && !stale && d.total === 0 && <p className="hint">{params.address || params.prefix || params.protocol ? "No matching routes" : "No routes"}</p>}
      {d && d.items.length > 0 && (
        <div className={"results xr-table" + (stale ? " xr-stale" : "")} aria-busy={stale || undefined}>
          <table>
            <thead>
              <tr>
                {perVrf && <th>VRF</th>}
                <th>Prefix</th><th>Next hop</th><th>Interface</th><th>Protocol</th><th>Metric</th>
              </tr>
            </thead>
            <tbody>
              {d.items.map((r, i) => (
                <tr key={`${r.context_uid}-${r.prefix}-${r.next_hop}-${i}`} className={r.longest && !stale ? "xr-best" : undefined}>
                  {perVrf && <td title={r.context_uid ?? undefined}>{r.vrf ?? ""}</td>}
                  <td className="mono">{r.prefix}{r.longest && !stale && <span className="xr-tag">Longest match</span>}</td>
                  <td className="mono">{r.discard ? `Discard (${r.discard})` : r.next_hop ?? "None"}</td>
                  <td>{r.interface ?? ""}</td>
                  <td>{r.protocol ?? ""}</td>
                  <td>{r.metric ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {d && d.total > PAGE && (
        <div className="xr-pager">
          <span className="hint">Rows {(d.offset + 1).toLocaleString()} to {Math.min(d.offset + PAGE, d.total).toLocaleString()} of {d.total.toLocaleString()}</span>
          <button type="button" className="secondary" disabled={offset === 0} onClick={() => turn(Math.max(0, offset - PAGE))}>Previous</button>
          <button type="button" className="secondary" disabled={offset + PAGE >= d.total} onClick={() => turn(offset + PAGE)}>Next</button>
        </div>
      )}
    </section>
  );
}
