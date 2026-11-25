import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryForm } from "./QueryForm";
import type { CannedQuery } from "../api/types";

const FIND_VLAN: CannedQuery = {
  key: "find-vlan",
  group: "topology",
  title: "Where is this VLAN",
  cypher: "MATCH (v:VlanInstance) WHERE v.vid = toInteger($vid) RETURN v",
  params: [{ name: "vid", label: "VLAN id", placeholder: "10" }],
};

describe("QueryForm param round-trip", () => {
  it("hands the typed param values to onRun on submit", async () => {
    const onRun = vi.fn();
    const user = userEvent.setup();
    render(<QueryForm query={FIND_VLAN} onRun={onRun} pending={false} />);

    const input = screen.getByLabelText("VLAN id");
    expect(input).toHaveAttribute("placeholder", "10");

    await user.type(input, "42");
    await user.click(screen.getByRole("button", { name: /run/i }));

    expect(onRun).toHaveBeenCalledWith({ vid: "42" });
  });

  it("renders no param row for a query with none declared", () => {
    const onRun = vi.fn();
    const noParams: CannedQuery = { key: "devices", group: "inventory", title: "Devices", cypher: "MATCH (d) RETURN d" };
    render(<QueryForm query={noParams} onRun={onRun} pending={false} />);

    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("disables Run while pending", () => {
    render(<QueryForm query={FIND_VLAN} onRun={vi.fn()} pending />);
    expect(screen.getByRole("button", { name: /running/i })).toBeDisabled();
  });
});

describe("QueryForm Cypher collapse and editing", () => {
  it("hides the Cypher until toggled", async () => {
    const user = userEvent.setup();
    render(<QueryForm query={FIND_VLAN} onRun={vi.fn()} pending={false} />);
    expect(screen.queryByText(/MATCH \(v:VlanInstance\)/)).not.toBeInTheDocument();
    const toggle = screen.getByRole("button", { name: /cypher/i });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(screen.getByText(/MATCH \(v:VlanInstance\)/)).toBeInTheDocument();
    await user.click(toggle);
    expect(screen.queryByText(/MATCH \(v:VlanInstance\)/)).not.toBeInTheDocument();
  });

  it("offers no Edit without onRunCypher", async () => {
    const user = userEvent.setup();
    render(<QueryForm query={FIND_VLAN} onRun={vi.fn()} pending={false} />);
    await user.click(screen.getByRole("button", { name: /cypher/i }));
    expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
  });

  it("runs an edited query through onRunCypher with the param values", async () => {
    const onRun = vi.fn();
    const onRunCypher = vi.fn();
    const user = userEvent.setup();
    render(
      <QueryForm query={FIND_VLAN} onRun={onRun} onRunCypher={onRunCypher} pending={false} />,
    );
    await user.type(screen.getByLabelText("VLAN id"), "42");
    await user.click(screen.getByRole("button", { name: /cypher/i }));
    await user.click(screen.getByRole("button", { name: "Edit" }));
    const area = screen.getByLabelText("Cypher query");
    await user.type(area, " LIMIT 5");
    await user.click(screen.getByRole("button", { name: "Run edited" }));
    expect(onRunCypher).toHaveBeenCalledWith(
      "MATCH (v:VlanInstance) WHERE v.vid = toInteger($vid) RETURN v LIMIT 5",
      { vid: "42" },
    );
    expect(onRun).not.toHaveBeenCalled();
  });

  it("Reset restores the original and the run goes back to the canned path", async () => {
    const onRun = vi.fn();
    const onRunCypher = vi.fn();
    const user = userEvent.setup();
    render(
      <QueryForm query={FIND_VLAN} onRun={onRun} onRunCypher={onRunCypher} pending={false} />,
    );
    await user.click(screen.getByRole("button", { name: /cypher/i }));
    await user.click(screen.getByRole("button", { name: "Edit" }));
    await user.type(screen.getByLabelText("Cypher query"), " LIMIT 5");
    await user.click(screen.getByRole("button", { name: "Reset" }));
    await user.click(screen.getByRole("button", { name: "Run" }));
    expect(onRun).toHaveBeenCalled();
    expect(onRunCypher).not.toHaveBeenCalled();
  });
});

describe("QueryForm required params", () => {
  it("marks a required param and focuses it when it is empty", () => {
    render(
      <QueryForm
        query={{
          key: "q-required",
          title: "One VLAN",
          group: "l2",
          cypher: "RETURN $vid",
          params: [{ name: "vid", label: "VLAN id", placeholder: "100" }],
        }}
        pending={false}
        onRun={() => {}}
      />,
    );
    const input = screen.getByLabelText("VLAN id");
    expect(input).toHaveAttribute("aria-required", "true");
    expect(document.activeElement).toBe(input);
  });
});

describe("QueryForm in two panes", () => {
  it("labels each pane's own input when two panes show one query", () => {
    render(
      <>
        <QueryForm query={FIND_VLAN} onRun={vi.fn()} pending={false} />
        <QueryForm query={FIND_VLAN} onRun={vi.fn()} pending={false} />
      </>,
    );
    const inputs = screen.getAllByLabelText("VLAN id");
    expect(inputs).toHaveLength(2);
    expect(inputs[0]).not.toBe(inputs[1]);
    expect(inputs[0].id).not.toBe(inputs[1].id);
  });
});
