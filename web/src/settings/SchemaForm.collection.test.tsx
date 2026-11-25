/**
 * The group parameters (collectors' SshSourceConfig / SourceConfig): a Literal
 * field renders as a closed <select>, never free text, and the collection
 * knobs (cadence, transport, time budgets) render together under their own
 * "Collection" fieldset.
 */

import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SchemaForm } from "./SchemaForm";
import type { SourceTypeSchema } from "../api/types";
import fixtures from "./schema.fixtures.json";

const NXOS_SCHEMA = fixtures.nxos as unknown as SourceTypeSchema;

// A minimal group-shaped schema: one connection field, one enum, two knobs.
const SCHEMA_GROUP: SourceTypeSchema = {
  type: "object",
  title: "GroupConfig",
  properties: {
    host: { type: "string", title: "Host" },
    transport: {
      type: "string",
      title: "Transport",
      enum: ["asyncssh", "paramiko"],
      default: "asyncssh",
    },
    interval_s: { type: "integer", title: "Collection interval (seconds)", default: 0 },
    timeout: { type: "integer", title: "Timeout", default: 120 },
  },
  required: ["host"],
};

describe("SchemaForm: enum fields", () => {
  it("renders a Literal as a select with exactly its allowed values", () => {
    render(<SchemaForm schema={SCHEMA_GROUP} mode="create" submitLabel="Create" onSubmit={vi.fn()} />);

    const transport = screen.getByLabelText("Transport") as HTMLSelectElement;
    expect(transport.tagName).toBe("SELECT");
    expect([...transport.options].map((o) => o.value)).toEqual(["asyncssh", "paramiko"]);
    expect(transport.value).toBe("asyncssh"); // the schema default, not blank
  });

  it("submits the selected enum value with the other collection defaults", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(<SchemaForm schema={SCHEMA_GROUP} mode="create" submitLabel="Create" onSubmit={onSubmit} />);

    await user.type(screen.getByLabelText(/Host/), "r1");
    await user.selectOptions(screen.getByLabelText("Transport"), "paramiko");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(onSubmit).toHaveBeenCalledWith({
      host: "r1",
      transport: "paramiko",
      interval_s: 0,
      timeout: 120,
    });
  });
});

describe("SchemaForm: the Collection fieldset", () => {
  it("groups the collection knobs and leaves the connection fields outside", () => {
    render(<SchemaForm schema={SCHEMA_GROUP} mode="create" submitLabel="Create" onSubmit={vi.fn()} />);

    const group = screen.getByRole("group", { name: "Collection" });
    expect(within(group).getByLabelText("Transport")).toBeInTheDocument();
    expect(within(group).getByLabelText("Collection interval (seconds)")).toBeInTheDocument();
    expect(within(group).getByLabelText("Timeout")).toBeInTheDocument();
    expect(within(group).queryByLabelText(/Host/)).not.toBeInTheDocument();
  });

  it("wires the real nxos schema: transport is a select inside Collection", () => {
    render(<SchemaForm schema={NXOS_SCHEMA} mode="create" submitLabel="Create" onSubmit={vi.fn()} />);

    const group = screen.getByRole("group", { name: "Collection" });
    const transport = within(group).getByLabelText("Transport") as HTMLSelectElement;
    expect(transport.tagName).toBe("SELECT");
    expect([...transport.options].map((o) => o.value)).toEqual(["asyncssh", "paramiko"]);
    expect(within(group).getByLabelText(/Collection interval/)).toBeInTheDocument();
  });

  it("renders no Collection fieldset for a schema without collection knobs", () => {
    const plain: SourceTypeSchema = {
      type: "object",
      title: "Plain",
      properties: { base_url: { type: "string", title: "Base URL" } },
      required: [],
    };
    render(<SchemaForm schema={plain} mode="create" submitLabel="Create" onSubmit={vi.fn()} />);
    expect(screen.queryByRole("group", { name: "Collection" })).not.toBeInTheDocument();
  });
});
