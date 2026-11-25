import { expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import type { MtuResult } from "../api/types";
import { MtuDetails } from "./MtuPanel";

it("displays a resolved NX-OS payload limit without unknown frame/tag semantics", () => {
  const result: MtuResult = {
    mode: "inventory",
    observations: [{
      uid: "mtu:synthetic",
      subject_uid: "port:synthetic",
      source: "nxos",
      source_target: "synthetic",
      source_field: "show interface | json:eth_mtu",
      raw_value_json: '"1500"',
      raw_basis: "ethernet_payload",
      profile_id: "ethernet_payload",
      profile_version: "1",
      metric: "l2_payload_mtu_bytes",
      normalized_value: 1500,
      bound_kind: "ceiling",
      assertion_kind: "operational",
      resolution_state: "explicit",
      gaps: [],
    }],
  };
  render(<MtuDetails result={result} />);
  expect(screen.getByText(/1,?500 B, Ethernet payload, ceiling/)).toBeInTheDocument();
  expect(screen.getByText("Ethernet/VLAN headers excluded")).toBeInTheDocument();
  expect(screen.queryByText(/unknown, depth/)).not.toBeInTheDocument();
  expect(screen.queryByText("Findings")).not.toBeInTheDocument();
});
