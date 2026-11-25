import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { TraceInfo } from "./TraceInfo";
import { FIXTURE_PATH_BLOCKED } from "../test/fixtures";

describe("TraceInfo", () => {
  it("leads a warning with the word warning", () => {
    const result = { ...FIXTURE_PATH_BLOCKED, warnings: ["one gate was not evaluated"] };
    const { container } = render(<TraceInfo result={result} open onToggle={() => {}} />);
    const first = container.querySelector("li");
    expect(first?.classList).toContain("warn");
    expect(first?.textContent?.startsWith("Warning ")).toBe(true);
    expect(first?.textContent).not.toContain("⚠");
  });
});
