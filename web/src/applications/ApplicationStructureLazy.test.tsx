/** The structure view opens in list mode, which must not load Cytoscape. */
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ApplicationStructure } from "./ApplicationStructure";
import type { BusinessApplicationDefinition } from "./types";

const { loaded } = vi.hoisted(() => ({ loaded: { graph: false } }));

vi.mock("../graph/cytoscape", async (importOriginal) => {
  loaded.graph = true;
  return importOriginal();
});

const DEFINITION: BusinessApplicationDefinition = {
  schema_version: 2,
  kind: "BusinessApplication",
  id: "webshop",
  name: "Webshop",
  state: "draft",
  services: [],
  groups: [{ id: "clients", name: "Clients", members: [{ id: "lan", address: "10.9.0.0/24" }] }],
  connections: [],
};

describe("ApplicationStructure in list mode", () => {
  it("does not load the graph module", () => {
    render(<ApplicationStructure definition={DEFINITION} />);
    expect(screen.getByRole("heading", { name: "Component groups" })).toBeInTheDocument();
    expect(loaded.graph).toBe(false);
  });
});
