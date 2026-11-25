import { describe, expect, it } from "vitest";
import { keyOf, type Row, type TableName } from "../render/types";
import { diff, history } from "../test/runs";
import { TierTable } from "./table";

function sorted(name: TableName, rows: Row[]): Row[] {
  return [...rows].sort((a, b) => keyOf(name, a).localeCompare(keyOf(name, b)));
}

describe("a tier table moved by its deltas", () => {
  const states = history(12);

  for (const name of ["render_t1", "render_t1_edges", "render_t2_ports"] as TableName[]) {
    it(`applies and unapplies every delta of ${name}`, () => {
      for (let k = 1; k < states.length; k++) {
        const delta = diff(name, states[k - 1][name], states[k][name]);
        const table = new TierTable(name, states[k - 1][name]);
        table.apply(delta);
        expect(sorted(name, table.present())).toEqual(sorted(name, states[k][name]));
        table.unapply(delta);
        expect(sorted(name, table.present())).toEqual(sorted(name, states[k - 1][name]));
      }
    });
  }

  it("keeps a removed row as absent and reports it as null", () => {
    const delta = diff("render_t1", states[3].render_t1, states[4].render_t1);
    const table = new TierTable("render_t1", states[3].render_t1);
    const changes = table.apply(delta);
    expect(changes).toContainEqual({ key: "dev:s1d3", row: null });
    expect(table.absent.has("dev:s1d3")).toBe(true);
    expect(table.rows.get("dev:s1d3")?.label).toBe("s1d3");
    expect(table.unapply(delta)).toContainEqual({ key: "dev:s1d3", row: expect.objectContaining({ uid: "dev:s1d3" }) });
    expect(table.absent.has("dev:s1d3")).toBe(false);
  });
});
