import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ResultsTable } from "./ResultsTable";
import type { QueryResult } from "../api/types";

const FIXTURE: QueryResult = {
  columns: ["hostname", "platform", "site"],
  data: [
    { row: ["core1", "vyos", "hq"] },
    { row: ["sw1", "unifi", "hq"] },
  ],
  truncated: false,
};

describe("ResultsTable", () => {
  it("renders the empty state before any query has run", () => {
    render(<ResultsTable result={null} />);
    expect(screen.getByText("No result")).toBeInTheDocument();
  });

  it("renders a fixture response as columns and rows", () => {
    render(<ResultsTable result={FIXTURE} />);

    expect(screen.getByText("2 rows")).toBeInTheDocument();
    for (const col of FIXTURE.columns) {
      expect(screen.getByRole("columnheader", { name: col })).toBeInTheDocument();
    }
    expect(screen.getByText("core1")).toBeInTheDocument();
    expect(screen.getByText("vyos")).toBeInTheDocument();
    expect(screen.getByText("sw1")).toBeInTheDocument();
    expect(screen.queryByText(/truncat/i)).not.toBeInTheDocument();
  });

  it("joins a list of values with commas, leaves an empty list blank and keeps nested values on one line", () => {
    render(
      <ResultsTable
        result={{
          columns: ["src", "ranges", "flag", "nested", "map", "lists"],
          data: [
            {
              row: [
                ["203.0.113.194", "203.0.113.195"],
                [],
                false,
                [{ a: 1 }],
                { name: "WEB-IN", ports: [80, 443] },
                [[1, 2], [3]],
              ],
            },
          ],
          truncated: false,
        }}
      />,
    );

    const cells = screen.getAllByRole("cell").map((c) => c.textContent);
    expect(cells[0]).toBe("203.0.113.194, 203.0.113.195");
    expect(cells[1]).toBe("");
    expect(cells[2]).toBe("false");
    expect(cells[3]).toBe("{a: 1}");
    expect(cells[4]).toBe("name: WEB-IN, ports: [80, 443]");
    expect(cells[5]).toBe("[1, 2], [3]");
    for (const c of cells) expect(c).not.toContain("\n");
  });

  it("shows a truncation notice when the backend capped the rows", () => {
    render(<ResultsTable result={{ ...FIXTURE, truncated: true }} />);
    expect(screen.getByRole("status")).toHaveTextContent("More than 2 rows");
  });

  it("tells an empty result from no result", () => {
    render(<ResultsTable result={{ columns: ["x"], data: [], truncated: false }} />);
    expect(screen.getByText("No rows")).toBeInTheDocument();
  });
});
