import { describe, expect, it } from "vitest";
import { nearestStep, stepElementId } from "./citations";

describe("nearestStep", () => {
  it("takes the copy of the step in the chip's own conversation", () => {
    const id = stepElementId("s1");
    document.body.innerHTML = `
      <aside class="drawer"><ol><li id="${id}">drawer copy</li></ol><p><button>chip</button></p></aside>
      <section class="pane"><ol><li id="${id}">pane copy</li></ol><p><button>chip</button></p></section>`;
    const [drawerChip, paneChip] = Array.from(document.querySelectorAll("button"));
    expect(nearestStep(paneChip, "s1")?.textContent).toBe("pane copy");
    expect(nearestStep(drawerChip, "s1")?.textContent).toBe("drawer copy");
    expect(nearestStep(paneChip, "nope")).toBeNull();
  });
});
