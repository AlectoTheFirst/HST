import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PathGraphView } from "./PathGraphView";
import { PathTreeView } from "./PathTreeView";
import { Inspector } from "./Inspector";
import { MtuDetails, MtuHopSummary, MtuLegSummary, hopMtuMark, mtuForLane, mtuStages } from "./MtuPanel";
import { FIXTURE_PATH_SINGLE, FIXTURE_PATH_ECMP } from "../test/fixtures";
import type { Hop, MtuConstraint, MtuObservation, MtuResult, MtuStage } from "../api/types";

function constraint(value: Partial<MtuConstraint> = {}): MtuConstraint {
  return {
    subject_uid: "if:r1-eth1",
    enforcement_key: "l3",
    enforcement: "l3",
    metric: "ipv4_mtu_bytes",
    direction: "tx",
    bound_kind: "ceiling",
    value_bytes: 1500,
    evidence_uids: ["mtu:1"],
    evidence_quality: ["observed"],
    ...value,
  };
}

function stage(value: Partial<MtuStage> = {}): MtuStage {
  return {
    stage_id: "s1",
    lane: "0",
    enforcement: "l3",
    applicability: "applicable",
    egress_subject_uid: "if:r1-eth1",
    context: { af: 4, direction: "tx", enforcement: "l3" },
    constraints: [constraint()],
    coverage: { gaps: [] },
    selection: "selected",
    ...value,
  };
}

function observation(value: Partial<MtuObservation> = {}): MtuObservation {
  return {
    uid: "mtu:1",
    subject_uid: "if:r1-eth1",
    source: "synthetic",
    source_target: "fixture",
    source_field: "ip_mtu",
    raw_value_json: "1500",
    raw_basis: "ip_packet",
    metric: "ipv4_mtu_bytes",
    normalized_value: 1500,
    assertion_kind: "operational",
    resolution_state: "explicit",
    ...value,
  };
}

function result(value: Partial<MtuResult> = {}): MtuResult {
  return {
    mode: "unfragmented",
    direction: "forward",
    requested_bytes: 1501,
    outcome: "fail",
    known_ceiling_bytes: 1500,
    guaranteed_bytes: null,
    coverage: { complete: false, truncated: false, exact_path_known: false, gaps: ["MTU_PATH_COVERAGE_INCOMPLETE"] },
    evidence_quality: ["observed"],
    bottleneck_stage_ids: ["s1"],
    findings: [{ code: "MTU_CAPACITY_DEFICIT", severity: "failure", detail: "1501 exceeds 1500." }],
    stages: [stage()],
    observations: [observation()],
    ...value,
  };
}

function hop(value: Partial<Hop> = {}): Hop {
  return { uid: "if:r1-eth1", kind: "Interface", label: "eth1", note: "", rank: 1, lane: 0, shared: false, ...value };
}

/** A two-lane connection as the backend returns it: the lanes carry the stages. */
function twoLanes(): MtuResult {
  return result({
    lane: null,
    known_ceiling_bytes: 9000,
    outcome: "conditional",
    stages: [],
    bottleneck_stage_ids: [],
    lanes: [
      result({ lane: "0", outcome: "fail", stages: [stage({ lane: "0" })] }),
      result({
        lane: "1",
        outcome: "pass",
        known_ceiling_bytes: 9000,
        guaranteed_bytes: 9000,
        bottleneck_stage_ids: ["s2"],
        stages: [stage({ stage_id: "s2", lane: "1", egress_subject_uid: "if:r1-eth2", constraints: [constraint({ subject_uid: "if:r1-eth2", value_bytes: 9000 })] })],
      }),
    ],
  });
}

describe("mtuForLane", () => {
  it("returns null without a result and for off", () => {
    expect(mtuForLane(undefined, 0)).toBeNull();
    expect(mtuForLane({ mode: "off" }, 0)).toBeNull();
  });

  it("answers a single-lane connection with the connection itself", () => {
    const value = result();
    expect(mtuForLane(value, 0)).toBe(value);
    expect(mtuForLane(value, 3)).toBe(value);
  });

  it("finds the lane entry of a split connection and nothing for an unknown lane", () => {
    const value = twoLanes();
    expect(mtuForLane(value, 1)?.outcome).toBe("pass");
    expect(mtuForLane(value, "0")?.outcome).toBe("fail");
    expect(mtuForLane(value, 2)).toBeNull();
  });

  it("collects nested stages once", () => {
    expect(mtuStages(twoLanes()).map((s) => s.stage_id)).toEqual(["s1", "s2"]);
  });
});

describe("hopMtuMark", () => {
  it("is absent without a result and for off", () => {
    expect(hopMtuMark(undefined, hop())).toBeNull();
    expect(hopMtuMark({ mode: "off" }, hop())).toBeNull();
  });

  it("marks a hop with its smallest known limit and nothing else", () => {
    const mark = hopMtuMark(result(), hop());
    expect(mark!.text).toMatch(/^MTU 1,?500 B$/);
    expect(mark!.title).toMatch(/IPv4 packet tx ceiling 1,?500 B/);
    const two = hopMtuMark(result({ stages: [stage({ constraints: [constraint(), constraint({ value_bytes: 9000 })] })] }), hop());
    expect(two!.text).toMatch(/^MTU 1,?500 B$/);
  });

  it("marks only a hop that carries a resolved limit", () => {
    const na = hopMtuMark(result({ stages: [stage({ applicability: "not_applicable", constraints: [], egress_subject_uid: "dev:r1" })], bottleneck_stage_ids: [] }), hop({ uid: "dev:r1" }));
    expect(na).toBeNull();
    expect(hopMtuMark(result(), hop({ uid: "dev:other" }))).toBeNull();
    const unresolved = hopMtuMark(result({ stages: [stage({ constraints: [constraint({ value_bytes: null, bound_kind: "unknown" })] })], bottleneck_stage_ids: [] }), hop());
    expect(unresolved).toBeNull();
  });

  it("matches a shared hop against every lane and a lane hop only against its lane", () => {
    const value = twoLanes();
    expect(hopMtuMark(value, hop({ uid: "if:r1-eth2", shared: true }))!.text).toMatch(/9,?000 B/);
    expect(hopMtuMark(value, hop({ uid: "if:r1-eth2", lane: 0 }))).toBeNull();
    expect(hopMtuMark(value, hop({ uid: "if:r1-eth2", lane: 1 }))!.text).toMatch(/9,?000 B/);
  });
});

describe("marks on the views", () => {
  it("names the mark in the title of a graph box and omits it for off", () => {
    const uid = FIXTURE_PATH_SINGLE.hops[7].uid;
    const value = result({ stages: [stage({ egress_subject_uid: uid })] });
    const { rerender } = render(<PathGraphView result={{ ...FIXTURE_PATH_SINGLE, mtu: value }} selection={null} onSelect={() => {}} />);
    const box = screen.getByRole("button", { name: /^eth0\.1, Interface/ });
    expect(box.querySelector("title")?.textContent).toMatch(/MTU 1,?500 B/);
    rerender(<PathGraphView result={{ ...FIXTURE_PATH_SINGLE, mtu: { mode: "off" } }} selection={null} onSelect={() => {}} />);
    expect(screen.queryByText(/MTU/)).not.toBeInTheDocument();
  });

  it("puts the hop line and the leg summary in the opened hops of the tree", async () => {
    const user = userEvent.setup();
    const uid = FIXTURE_PATH_SINGLE.hops[1].uid;
    const value = result({ stages: [stage({ egress_subject_uid: uid, lane: String(FIXTURE_PATH_SINGLE.hops[1].lane) })] });
    const { rerender } = render(<PathTreeView result={{ ...FIXTURE_PATH_SINGLE, mtu: value }} selection={null} onSelect={() => {}} />);
    expect(screen.queryByText(/IPv4 packet tx ceiling 1,?500 B/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open all hops" }));
    expect(screen.getByText(/IPv4 packet tx ceiling 1,?500 B/)).toBeInTheDocument();
    const leg = screen.getByLabelText("MTU leg 0");
    expect(leg).toHaveTextContent("MTU fail");
    expect(leg).toHaveTextContent(/known ceiling 1,?500 B/);
    expect(leg).toHaveTextContent("guaranteed unknown");
    expect(leg).toHaveTextContent("coverage incomplete");
    rerender(<PathTreeView result={{ ...FIXTURE_PATH_SINGLE, mtu: { mode: "off" } }} selection={null} onSelect={() => {}} />);
    expect(screen.queryByText(/IPv4 packet/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText("MTU leg 0")).not.toBeInTheDocument();
  });

  it("gives each ECMP leg its own lane summary", async () => {
    const user = userEvent.setup();
    render(<PathTreeView result={{ ...FIXTURE_PATH_ECMP, mtu: twoLanes() }} selection={null} onSelect={() => {}} />);
    await user.click(screen.getByRole("button", { name: "Open all hops" }));
    expect(screen.getByLabelText("MTU leg 0")).toHaveTextContent("MTU fail");
    expect(screen.getByLabelText("MTU leg 1")).toHaveTextContent("MTU pass");
    expect(screen.getByLabelText("MTU leg 1")).toHaveTextContent(/guaranteed 9,?000 B/);
  });

  it("shows the leg summary and findings in the inspector for a leg selection", () => {
    const value = result();
    render(<Inspector selection={{ type: "leg", data: FIXTURE_PATH_SINGLE.legs[0] }} result={{ ...FIXTURE_PATH_SINGLE, mtu: value }} open onToggle={() => {}} />);
    expect(screen.getByLabelText("MTU leg 0")).toHaveTextContent(/known ceiling 1,?500 B/);
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText("1501 exceeds 1500.")).toBeInTheDocument();
  });
});

describe("MtuHopSummary and MtuLegSummary", () => {
  it("renders inventory as inventory and nothing for off", () => {
    const { container, rerender } = render(<MtuLegSummary result={result({ mode: "inventory", outcome: "not_assessed", requested_bytes: null })} lane={0} />);
    expect(screen.getByLabelText("MTU leg 0")).toHaveTextContent("MTU inventory");
    expect(screen.queryByText(/target/)).not.toBeInTheDocument();
    rerender(<MtuLegSummary result={{ mode: "off" }} lane={0} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows fits known limits and names the uncovered endpoints", () => {
    const value = result({
      outcome: "fits_known_limits",
      guaranteed_bytes: null,
      coverage: {
        complete: false, truncated: false, exact_path_known: false,
        gaps: ["MTU_ENDPOINT_UNKNOWN"], uncovered: ["source-endpoint", "path-beyond-twin"],
      },
    });
    render(<MtuLegSummary result={value} lane={0} />);
    const leg = screen.getByLabelText("MTU leg 0");
    expect(leg).toHaveTextContent("MTU fits known limits");
    expect(leg).toHaveTextContent("not covered: source endpoint, path beyond the twin");
  });

  it("lists the hop's limits and nothing on a hop without a limit", () => {
    const { container, rerender } = render(<MtuHopSummary result={result()} hop={hop()} />);
    expect(screen.getByText(/^IPv4 packet tx ceiling 1,?500 B$/)).toBeInTheDocument();
    rerender(<MtuHopSummary result={result({ bottleneck_stage_ids: [] })} hop={hop({ uid: "dev:other" })} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("MtuDetails", () => {
  it("filters stages by subject and shows raw and normalized evidence", () => {
    render(
      <MtuDetails
        result={result({
          stages: [
            stage(),
            stage({ stage_id: "s2", egress_subject_uid: "if:other", constraints: [constraint({ subject_uid: "if:other", value_bytes: 9000, evidence_uids: ["mtu:2"], inherited_from: ["policy:fabric"], evidence_quality: ["inherited"] })] }),
          ],
          observations: [observation(), observation({ uid: "mtu:2", subject_uid: "if:other", raw_value_json: "9000", normalized_value: 9000 })],
        })}
        subjectUid="if:other"
        lane="0"
      />,
    );
    const details = screen.getByRole("region", { name: "MTU enforcement and evidence" });
    expect(details.querySelectorAll("ol.mtu-stages > li")).toHaveLength(1);
    expect(within(details).getByText(/ceiling 9,?000 B/)).toBeInTheDocument();
    expect(within(details).getByText(/inherited from policy:fabric/)).toBeInTheDocument();
    expect(within(details).getByText("Raw and normalized evidence")).toBeInTheDocument();
    expect(within(details).getByText(/ip_mtu: 9000 \(ip packet\)/)).toBeInTheDocument();
    expect(within(details).queryByText(/ip_mtu: 1500/)).not.toBeInTheDocument();
  });

  it("states no enforcement stages for a selection without stages", () => {
    render(<MtuDetails result={result({ stages: [] })} subjectUid="if:none" lane="0" />);
    expect(screen.getByText("No enforcement stages")).toBeInTheDocument();
  });

  it("names an unresolved subject with no observation", () => {
    render(
      <MtuDetails
        result={result({
          stages: [
            stage({ stage_id: "s3", enforcement: "l2", egress_subject_uid: "dev:ap1/port/port0", constraints: [] }),
          ],
          observations: [],
        })}
        subjectUid="dev:ap1/port/port0"
        lane="0"
      />,
    );
    expect(screen.getByText("dev:ap1/port/port0")).toBeInTheDocument();
    expect(screen.getByText("No resolved limit")).toBeInTheDocument();
  });

  it("shows encapsulation, stage gaps and PMTUD feedback", () => {
    const carrier = stage({ encapsulation: [{ kind: "vxlan", operation: "encapsulate", profile_id: "vxlan-ipv4" }], coverage: { gaps: ["MTU_ENCAP_UNKNOWN"] } });
    const nested = result({
      stages: [carrier],
      candidates: [result({ stages: [carrier] })],
      feedback: [{ outcome: "blocked", packet: { af: 4, source_ip: "192.0.2.1", destination_ip: "192.0.2.9", icmp_type: 3, icmp_code: 4, quoted_flow_json: "{}", connection_id: "original" } }],
    });
    expect(mtuStages(nested)).toHaveLength(1);
    render(<MtuDetails result={nested} lane="0" />);
    expect(screen.getByText(/Encapsulation: vxlan \(encapsulate, profile vxlan-ipv4\)/)).toBeInTheDocument();
    expect(screen.getByText(/Gaps: MTU_ENCAP_UNKNOWN/)).toBeInTheDocument();
    expect(screen.getByText(/blocked: IPv4 ICMP type 3, code 4/)).toBeInTheDocument();
  });
});
