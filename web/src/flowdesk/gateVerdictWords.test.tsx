import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { PathGraphView } from "./PathGraphView";
import { PathTreeView } from "./PathTreeView";
import { FIXTURE_PATH_BLOCKED, FIXTURE_PATH_PARTITION } from "../test/fixtures";

const noop = () => {};

describe("gate verdicts in words", () => {
  it("puts blocked in the sub line of the blocking rulebase in the graph", () => {
    render(<PathGraphView result={FIXTURE_PATH_BLOCKED} selection={null} onSelect={noop} />);
    const box = screen.getByRole("button", { name: "IOT-LAN, FwRulebase, path 1" });
    const words = box.querySelectorAll(".pg-verdict.bad");
    expect(words).toHaveLength(1);
    expect(words[0].textContent).toBe("blocked");
    expect(box.querySelector(".pg-rect")).not.toBeNull();
    expect(box.classList).toContain("v-bad");
  });

  it("states permitted on every deciding rulebase of a permitted path", () => {
    const fw = FIXTURE_PATH_PARTITION.hops.find((h) => h.kind === "FwRulebase");
    const result = {
      ...FIXTURE_PATH_PARTITION,
      legs: FIXTURE_PATH_PARTITION.legs.map((l) => ({ ...l, fw_uid: fw?.uid })),
    };
    const { container } = render(<PathGraphView result={result} selection={null} onSelect={noop} />);
    const words = Array.from(container.querySelectorAll(".pg-verdict"));
    expect(words.length).toBeGreaterThan(0);
    for (const word of words) {
      expect(word.classList).toContain("ok");
      expect(word.textContent).toBe("permitted");
    }
  });

  it("states not decided on an indeterminate leg", () => {
    const fw = FIXTURE_PATH_PARTITION.hops.find((h) => h.kind === "FwRulebase");
    const result = {
      ...FIXTURE_PATH_PARTITION,
      legs: [{ ...FIXTURE_PATH_PARTITION.legs[0], fw_uid: fw?.uid, indeterminate: true }],
    };
    const { container } = render(<PathGraphView result={result} selection={null} onSelect={noop} />);
    const words = container.querySelectorAll(".pg-verdict");
    expect(words).toHaveLength(1);
    expect(words[0].classList).toContain("warn");
    expect(words[0].textContent).toBe("not decided");
  });

  it("states blocked on the rulebase item of the tree, with no verdict aria-label", () => {
    const { container } = render(<PathTreeView result={FIXTURE_PATH_BLOCKED} selection={null} onSelect={noop} />);
    const item = screen.getAllByRole("treeitem").find((r) => r.textContent?.includes("IOT-LAN"))!;
    const word = item.querySelector(".pt-pill.bad");
    expect(word?.textContent).toBe("blocked");
    expect(word?.hasAttribute("aria-label")).toBe(false);
    expect(container.textContent).not.toContain("verdict");
  });
});
