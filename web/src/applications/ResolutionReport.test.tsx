import { render, screen, within } from "@testing-library/react";
import { ResolutionReport } from "./ResolutionReport";
import type { GenerationReport } from "./types";

const REFERENCE = {
  snapshot: "4000",
  manifest_sha256: "a".repeat(64),
  estate: "test",
  observation_floor_ms: null,
};

function report(overrides: Partial<GenerationReport> = {}): GenerationReport {
  return {
    generation_id: "g1",
    snapshot: REFERENCE,
    definition_digest: "e".repeat(64),
    references: [],
    related: [],
    blocking: [],
    ...overrides,
  };
}

describe("Resolution report", () => {
  it("lists each related object with its reason and only counts the other search results", () => {
    render(
      <ResolutionReport
        report={report({
          related: [
            {
              uid: "tun:wireguard:dev:gw~peer-a",
              label: "Tunnel",
              name: "peer-a",
              relation: "returned by search_objects at step 1",
              reason:
                "policy_route_sources at step 2 started from it and returned a written member",
            },
            {
              uid: "ep:tv",
              label: "Endpoint",
              name: "tv-streaming",
              relation: "returned by search_objects at step 4",
              reason: "the description names streaming",
            },
          ],
          related_omitted: 50,
        })}
        definition={null}
        onBind={() => undefined}
      />,
    );

    const list = screen.getByRole("list", { name: "Related objects" });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent(
      "peer-a tun:wireguard:dev:gw~peer-a (Tunnel), returned by search_objects at step 1: policy_route_sources at step 2 started from it and returned a written member",
    );
    expect(items[1]).toHaveTextContent("the description names streaming");

    // the other search results are a collapsed count
    const others = screen.getByText("50 other objects returned by searches").closest("details");
    expect(others).not.toBeNull();
    expect(others).not.toHaveAttribute("open");
    expect(screen.queryByText(/host-/)).not.toBeInTheDocument();
  });

  it("shows the count alone when no related object is listed", () => {
    render(
      <ResolutionReport
        report={report({ related_omitted: 1 })}
        definition={null}
        onBind={() => undefined}
      />,
    );

    expect(screen.getByRole("heading", { name: "Found and not written" })).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Related objects" })).not.toBeInTheDocument();
    expect(screen.getByText("1 other object returned by searches")).toBeInTheDocument();
  });

  it("shows no related section when the searches returned nothing else", () => {
    render(<ResolutionReport report={report()} definition={null} onBind={() => undefined} />);

    expect(
      screen.queryByRole("heading", { name: "Found and not written" }),
    ).not.toBeInTheDocument();
  });
});
