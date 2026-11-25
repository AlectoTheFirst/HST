import { useEffect, useRef, useState } from "react";
import { fetchFlows, type FlowsResponse } from "../../applications/flows";

/** Loads the flow overlay of one application revision at one run. */
export type FlowLoader = (application: string, run: number, revision?: number) => Promise<FlowsResponse>;

/** The flow overlays kept, one per (application, revision, run); the oldest goes first. */
export const FLOW_CACHE = 32;

interface Result {
  data?: FlowsResponse;
  error?: string;
}

export function flowKey(application: string, revision: number | undefined, run: number): string {
  return `${application}|${revision ?? "latest"}|${run}`;
}

/**
 * The stored flow overlay of `application` at `run`, read once per (application, revision, run): a scrub back to a
 * run already read shows it from the cache. Only stored evaluations are read; nothing is evaluated or traced.
 * With no application or no run there is nothing to read.
 */
export function useFlows(
  application: string | null,
  revision: number | undefined,
  run: number | null,
  load: FlowLoader = fetchFlows,
): { data: FlowsResponse | null; error: string | null; loading: boolean } {
  const [loaded, setLoaded] = useState<ReadonlyMap<string, Result>>(new Map());
  const pending = useRef(new Set<string>());
  const key = application && run !== null ? flowKey(application, revision, run) : null;

  useEffect(() => {
    if (!application || run === null || !key || loaded.has(key) || pending.current.has(key)) return;
    pending.current.add(key);
    const keep = (result: Result) => {
      pending.current.delete(key);
      setLoaded((previous) => {
        const next = new Map(previous);
        next.set(key, result);
        while (next.size > FLOW_CACHE) next.delete(next.keys().next().value as string);
        return next;
      });
    };
    load(application, run, revision).then(
      (data) => keep({ data }),
      (e: unknown) => keep({ error: e instanceof Error ? e.message : String(e) }),
    );
  }, [application, revision, run, key, loaded, load]);

  const result = key ? loaded.get(key) : undefined;
  return { data: result?.data ?? null, error: result?.error ?? null, loading: key !== null && result === undefined };
}
