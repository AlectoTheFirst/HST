// @vitest-environment node
//
// The card box against the card CSS.
import { describe, expect, it } from "vitest";
// @ts-expect-error -- "fs" has no type declarations in scope here
import { readFileSync } from "fs";
// @ts-expect-error -- "url" has no type declarations in scope here
import { fileURLToPath } from "url";
import { CARD_FIXED_PX } from "./scene";

const css = readFileSync(fileURLToPath(new URL("../hst.css", import.meta.url)), "utf8") as string;

function rule(selector: string): string {
  return css.slice(css.indexOf(`${selector} {`)).split("}")[0];
}

function px(text: string, prop: string): number[] {
  return (new RegExp(`\\b${prop}:\\s*([^;]+);`).exec(text)?.[1] ?? "").split(/\s+/).map((x) => parseFloat(x));
}

describe("the card box", () => {
  it("takes the fixed width of the card CSS: the padding, the chip, the column gap and the border", () => {
    const card = rule(".hst-label.hst-card");
    const [, right, , left] = px(card, "padding");
    const [gap] = px(card, "column-gap");
    const [border] = px(card, "border");
    const [chip] = px(rule(".hst-card-chip"), "width");
    expect(left + chip + gap + right + 2 * border).toBe(CARD_FIXED_PX);
  });
});
