/**
 * The catalog queries that answer for one object: an entry whose param picks
 * a value of one of the object's labels by a property the object carries. The
 * value comes from the object. An entry with another required param needs more
 * than the object and is left out. Lookups match by name, as the pickers do, so
 * a repeated name answers for every object that carries it.
 */
import type { CannedQuery } from "../api/types";

export interface ObjectQuery {
  entry: CannedQuery;
  param: string;
  value: string;
  /** The object is the query's subject (a required param). */
  lookup: boolean;
}

export function objectQueries(
  catalog: ReadonlyArray<CannedQuery>,
  labels: ReadonlyArray<string>,
  properties: Readonly<Record<string, unknown>>,
): ObjectQuery[] {
  const out: ObjectQuery[] = [];
  for (const entry of catalog) {
    const params = entry.params ?? [];
    const match = params.find((p) => {
      if (!p.picker || !labels.includes(p.picker.label)) return false;
      const value = properties[p.picker.property];
      return typeof value === "string" ? value.trim() !== "" : typeof value === "number";
    });
    if (!match || !match.picker) continue;
    if (params.some((p) => p !== match && !p.optional)) continue;
    out.push({
      entry,
      param: match.name,
      value: String(properties[match.picker.property]),
      lookup: !match.optional,
    });
  }
  return out;
}
