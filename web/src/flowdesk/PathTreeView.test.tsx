import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { PathTreeView } from "./PathTreeView";
import { FIXTURE_PATH_LEAF_SPINE } from "../test/fixtures";
import type { Selection } from "./selection";

function Harness({ onSelect }: { onSelect?: (s: Selection) => void }) {
  const [selection, setSelection] = useState<Selection | null>(null);
  return (
    <PathTreeView
      result={FIXTURE_PATH_LEAF_SPINE}
      selection={selection}
      onSelect={(s) => {
        setSelection(s);
        onSelect?.(s);
      }}
    />
  );
}

const tree = () => screen.getByRole("tree", { name: "Path tree" });
const rows = () => within(tree()).getAllByRole("treeitem");
const current = () => document.getElementById(tree().getAttribute("aria-activedescendant") ?? "")!;

describe("PathTreeView", () => {
  it("shows each branch to its end, with guides only at forks", () => {
    render(<Harness />);
    const items = rows();
    expect(items).toHaveLength(18);
    expect(items.map((r) => r.querySelector(".pt-pfx")?.textContent)).toEqual([
      "", "", "|-- ", "|   |-- ", "|   |   ", "|   |   ", "|   |   ", "|   |   ", "|   `-- ", "|       ",
      "`-- ", "    |-- ", "    |   ", "    |   ", "    |   ", "    |   ", "    `-- ", "        ",
    ]);
    expect(items.filter((r) => r.textContent?.includes("border1"))).toHaveLength(2);
    expect(items[9]).toHaveAttribute("aria-level", "3");
    expect(items[9].textContent).toContain("Path 2");
    expect(items[9].querySelector(".pt-end .pt-pill.bad")).not.toBeNull();
    expect(tree().textContent).not.toMatch(/same as/i);
  });

  it("moves and selects with j and k, opens with l, closes with h", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(<Harness onSelect={onSelect} />);
    tree().focus();
    await user.keyboard("j");
    expect(current().textContent).toContain("leaf1");
    expect(onSelect).toHaveBeenLastCalledWith({ type: "hop", data: expect.objectContaining({ uid: "dev:leaf1" }) });
    expect(current()).toHaveAttribute("aria-expanded", "false");
    await user.keyboard("l");
    expect(current()).toHaveAttribute("aria-expanded", "true");
    expect(rows()).toHaveLength(18 + 16);
    await user.keyboard("j");
    expect(current().textContent).toContain("Path 1");
    expect(current().textContent).toContain("vlan20");
    expect(onSelect).toHaveBeenLastCalledWith({ type: "hop", data: expect.objectContaining({ uid: "if:leaf1/vlan20" }) });
    // h on a hop line closes its item and goes back to it
    await user.keyboard("h");
    expect(rows()).toHaveLength(18);
    expect(current().textContent).toContain("leaf1");
    await user.keyboard("k");
    expect(current().textContent).toContain("10.20.1.15");
  });

  it("goes to the fork above with h on a closed item", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(rows()[5]);
    expect(current().textContent).toContain("rules");
    await user.keyboard("h");
    expect(current().textContent).toContain("spine1");
  });

  it("opens an item with a click on its [+]", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const leaf = rows()[1];
    await user.click(leaf.querySelector(".pt-tog")!);
    expect(leaf).toHaveAttribute("aria-expanded", "true");
    expect(leaf.querySelector(".pt-tog")?.textContent).toBe("[-]");
  });

  it("dims the rows that do not match the filter and opens nothing", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.type(screen.getByRole("searchbox", { name: "Filter" }), "border2");
    const items = rows();
    expect(items).toHaveLength(18);
    expect(items.filter((r) => r.classList.contains("match"))).toHaveLength(2);
    expect(items.filter((r) => r.classList.contains("dim"))).toHaveLength(16);
  });

  it("goes to the filter with /", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    tree().focus();
    await user.keyboard("/");
    expect(screen.getByRole("searchbox", { name: "Filter" })).toHaveFocus();
  });

  it("copies the tree as plain text with the same guides", async () => {
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText");
    render(<Harness />);
    await user.click(screen.getByRole("button", { name: "Copy as text" }));
    const text = writeText.mock.calls.at(-1)?.[0] ?? "";
    const lines = text.split("\n");
    expect(lines).toHaveLength(18);
    expect(lines[2]).toBe("|-- spine1  Device  spine1 note  ECMP 2");
    expect(lines[17]).toBe("        acl-in  blocked  deny (rule 40 iot-to-dc)  Path 4 blocked by acl-in rule 40");
    tree().focus();
    await user.keyboard("y");
    expect(writeText).toHaveBeenCalledTimes(2);
  });

  it("opens and closes every item's hops", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("button", { name: "Open all hops" }));
    expect(rows().length).toBeGreaterThan(18);
    await user.click(screen.getByRole("button", { name: "Close all hops" }));
    expect(rows()).toHaveLength(18);
  });
});
