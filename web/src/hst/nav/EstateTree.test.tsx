import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { createNullRenderer } from "../render/null";
import type { TableName } from "../render/types";
import { base } from "../test/estate";
import { showcase } from "../test/showcase";
import EstateTree, { estateTree } from "./EstateTree";

function scene() {
  const t = showcase();
  const r = createNullRenderer();
  r.setTier("layout", base(t));
  for (const name of ["render_t0", "render_t1"] as TableName[]) r.setTier(name, t[name]);
  return r.scene;
}

describe("the estate tree", () => {
  it("lists the sites by name with their blocks and device counts", () => {
    const tree = estateTree(scene());
    expect(tree.map((s) => [s.label, s.count])).toEqual([
      ["Branch Network", 4],
      ["Data Center South", 6],
      ["Headquarters", 30],
    ]);
    expect(tree[2].children.map((b) => b.label)).toEqual(["Campus", "Data Center North", "Internet Edge", "Perimeter", "WAN Region"]);
  });

  it("filters by the search box and flies to a click", () => {
    const onFocus = vi.fn();
    render(<EstateTree scene={scene()} version={0} selected={null} onFocus={onFocus} />);
    fireEvent.change(screen.getByRole("searchbox", { name: "Search the estate" }), { target: { value: "perim" } });
    const nav = screen.getByRole("navigation", { name: "Estate" });
    expect(within(nav).queryByText("Campus")).toBeNull();
    fireEvent.click(within(nav).getByRole("button", { name: /Perimeter/ }));
    expect(onFocus).toHaveBeenCalledWith("block:hq:firewall");
  });

  it("stays hidden while the page keeps it closed, and asks the page to open it", () => {
    const onOpen = vi.fn();
    render(<EstateTree scene={scene()} version={0} selected={null} onFocus={vi.fn()} open={false} onOpen={onOpen} />);
    expect(screen.queryByRole("navigation", { name: "Estate" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Estate/ }));
    expect(onOpen).toHaveBeenCalledWith(true);
  });
});
