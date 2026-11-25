import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ObjectQueries } from "./ObjectQueriesSection";
import type { CannedQuery } from "../api/types";

const CATALOG: CannedQuery[] = [
  {
    key: "zpa-app-segment",
    group: "zscaler",
    title: "App segment",
    cypher: "RETURN 1",
    params: [{ name: "segment", label: "App segment", picker: { label: "ZpaAppSegment", property: "name" } }],
  },
];

describe("ObjectQueries", () => {
  it("opens a query with the object's value filled in", async () => {
    const onAsk = vi.fn();
    render(<ObjectQueries catalog={CATALOG} labels={["ZpaAppSegment"]} properties={{ name: "app-crm" }} onAsk={onAsk} />);
    await userEvent.setup().click(screen.getByRole("button", { name: "App segment" }));
    expect(onAsk).toHaveBeenCalledWith("zpa-app-segment", { segment: "app-crm" });
  });

  it("renders nothing for an object no query answers for", () => {
    const { container } = render(
      <ObjectQueries catalog={CATALOG} labels={["Device"]} properties={{ name: "r1" }} onAsk={() => {}} />,
    );
    expect(container.textContent).toBe("");
  });
});
