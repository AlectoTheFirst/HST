/** The Predicted pane shows what an engine computes for the change. */

import { formatSnapshotDate } from "../flowdesk/SnapshotPicker";
import type {
  AssessImpactResult,
  FlowPaths,
  ModelError,
  MtuPathSide,
  NextHopRecord,
  PathGroup,
  PathSide,
  PredictedBgpRow,
  PredictedResult,
  PredictRoutesResult,
  RoutingBgpSessionDependency,
  RoutingConsequence,
  SimulatedFlow,
  SimulatePolicyChangeResult,
  WithdrawalSiteScope,
  WithdrawalWalk,
} from "./assessImpact";
import {
  FLOW_OUTSIDE_CHANGE,
  flowBasisReasons,
  flowNotEstablished,
  resultSnapshot,
  resultsNotEstablished,
} from "./assessImpact";
import { BucketSection, DeviceIdentity, ListSection } from "./Buckets";
import { ExportControl } from "./ExportControl";
import { useNamer } from "../shell/deviceNames";
import "./changesim.css";

function namedGapLines(errors: readonly ModelError[]): string[] {
  return errors.map((e) => {
    const detail = e.detail || e.kind;
    return `${e.kind}: ${detail}${e.subject ? ` (${e.subject})` : ""}`;
  });
}

/** `assess_impact` names its gaps as plain strings, `predict_routes` and
 *  `simulate_policy_change` as `{kind, detail, subject}` records; all reach the
 *  strip as one line each. */
function modelErrorLines(result: PredictedResult): string[] {
  if (result.tool === "assess_impact") return result.impact.model_errors ?? [];
  if (result.tool === "simulate_policy_change") return namedGapLines(result.policy.model_errors);
  return namedGapLines(result.routes.model_errors);
}

function ImpactPrediction({ impact }: { impact: AssessImpactResult }) {
  const name = useNamer();
  return (
    <div className="chgsim-panebody">
      <DeviceIdentity device={impact.device} />
      <BucketSection
        title="Single-homed prefixes"
        bucket={impact.single_homed_prefixes}
        render={(p) => `${p.cidr ?? p.uid}${p.kind ? ` (${p.kind})` : ""}`}
      />
      <BucketSection
        title="Single-homed endpoints"
        bucket={impact.single_homed_endpoints}
        render={(e) => e.name ?? e.uid}
      />
      <BucketSection
        title="Redundancy groups"
        bucket={impact.redundancy_groups}
        render={(g) => {
          const label = `${g.name ?? g.uid}${g.kind ? ` (${g.kind})` : ""}${g.role ? `, ${g.role}` : ""}`;
          const survivors = g.has_other_members
            ? `surviving members ${g.other_members.map((m) => m.hostname ?? name(m.uid)).join(", ")}`
            : "no surviving member";
          return `${label}, ${survivors}`;
        }}
      />
      <BucketSection
        title="Interfaces"
        bucket={impact.interfaces}
        render={(i) => i.name ?? i.uid}
      />
      <BucketSection
        title="Tunnels"
        bucket={impact.tunnels}
        render={(t) => `${name(t.uid)}${t.encap ? ` (${t.encap})` : ""}${t.state ? `, ${t.state}` : ""}`}
      />
      <BucketSection
        title="BGP sessions"
        bucket={impact.bgp_sessions}
        render={(s) =>
          `${s.local_ip ?? "not recorded"} to ${s.peer_ip ?? "not recorded"}${s.peer_asn != null ? ` (AS${s.peer_asn})` : ""}`
        }
      />
      <BucketSection
        title="FHRP groups"
        bucket={impact.fhrp_groups}
        render={(f) =>
          `${f.vip ?? f.uid}${f.kind ? ` (${f.kind})` : ""}${f.group_id != null ? `, group ${f.group_id}` : ""}`
        }
      />
    </div>
  );
}

function RoutePrediction({ routes }: { routes: PredictRoutesResult }) {
  const name = useNamer();
  return (
    <div className="chgsim-panebody">
      <div className="chgsim-device">
        <div className="chgsim-devicename" title={routes.scope}>{name(routes.scope)}</div>
        <div className="chgsim-devicemeta">
          {[routes.scope_kind, `${routes.row_count} predicted rows`].filter(Boolean).join(", ")}
        </div>
      </div>
      {routes.vrfs.length === 0 ? (
        <p className="chgsim-bucketempty">no predicted rows</p>
      ) : (
        routes.vrfs.map((vrf) => (
          <ListSection
            key={vrf.context_uid}
            title={name(vrf.context_uid)}
            items={vrf.rows}
            count={vrf.row_count}
            truncated={vrf.truncated}
            render={(row) => {
              const path = row.as_path?.length ? `AS path ${row.as_path.join(" ")}` : "";
              const communities = row.communities?.length
                ? `communities ${row.communities.join(" ")}`
                : "";
              return [
                `${row.prefix ?? "prefix not recorded"} via ${row.next_hop ?? "next hop not recorded"}`,
                path,
                row.local_pref != null && `local pref ${row.local_pref}`,
                row.med != null && `MED ${row.med}`,
                row.origin && `origin ${row.origin}`,
                communities,
              ]
                .filter(Boolean)
                .join(", ");
            }}
          />
        ))
      )}
    </div>
  );
}

/** An absent side is a path that only the other trace walked. */
function sideText(side: PathSide | null | undefined): string {
  if (!side) return "no path";
  if (side.blocked) return "blocked";
  if (side.indeterminate) return "not decided";
  return "permitted";
}

/** `MtuPathSide.outcome` in words. */
function mtuOutcomeWords(outcome: MtuPathSide["outcome"]): string {
  switch (outcome) {
    case "pass":
      return "pass";
    case "fail":
      return "fail";
    case "fragmentation_required":
      return "fragmentation required";
    case "conditional":
      return "conditional";
    case "unknown":
      return "unknown";
    default:
      return "not assessed";
  }
}

/** One side of a group's MTU outcome, as one clause. */
function mtuSideClause(side: MtuPathSide | null | undefined): string | null {
  if (!side || !side.outcome) return null;
  const where = side.bottleneck?.length ? ` at ${side.bottleneck.join(", ")}` : "";
  const ceiling = side.known_ceiling_bytes != null ? ` (${side.known_ceiling_bytes} B)` : "";
  return `MTU ${mtuOutcomeWords(side.outcome)}${where}${ceiling}`;
}

/** A group's MTU outcome, before and after, as one line. */
function mtuOutcomeLine(group: PathGroup): string | null {
  const clauses = [mtuSideClause(group.mtu_before), mtuSideClause(group.mtu_after)].filter(
    (c): c is string => c != null,
  );
  return clauses.length ? clauses.join(" to ") : null;
}

/** A sample and its whole count, in one cell. */
function sampleText(sample: readonly string[] | undefined, whole: number | undefined): string {
  const listed = sample ?? [];
  if (listed.length === 0) return "not recorded";
  const rest = (whole ?? listed.length) - listed.length;
  return rest > 0 ? `${listed.join(", ")} and ${rest} more` : listed.join(", ");
}

/** One flow's header line: source, destination and service. */
function flowHead(entry: SimulatedFlow): string {
  const spec = entry.flow ?? {};
  const where = `${spec.src ?? "not recorded"} to ${spec.dst ?? "not recorded"}`;
  const service = [spec.proto, spec.port].filter((v) => v != null && v !== "").join(" ");
  return service ? `${where} (${service})` : where;
}

/** The flow's result before and after the change, in the tracer's prose. */
function resultLine(entry: SimulatedFlow): string {
  const before = entry.before?.detail ?? entry.before?.result.word ?? "no result recorded";
  const after = entry.after?.detail ?? entry.after?.result.word ?? "no result recorded";
  return entry.result_changed ? `before ${before}, after ${after}` : `result unchanged: ${before}`;
}

/** Whether the flow crosses none of the devices the change set alters. */
function outsideTheChange(entry: SimulatedFlow): boolean {
  return entry.model_error?.kind === FLOW_OUTSIDE_CHANGE;
}

/** The statement for a flow whose comparison is not established. */
function notEstablishedText(entry: SimulatedFlow): string {
  const reasons = flowBasisReasons(entry);
  return `Comparison not established: ${reasons.length ? reasons.join("; ") : "no reason stated"}`;
}

function flowMeta(entry: SimulatedFlow): string {
  if (outsideTheChange(entry)) {
    return "crosses none of the changed devices";
  }
  if (flowNotEstablished(entry)) return "result neither changed nor unchanged";
  const paths = entry.paths;
  if (!paths) return resultLine(entry);
  return [
    `${paths.path_count_before} ${paths.path_count_before === 1 ? "path" : "paths"} before`,
    `${paths.path_count_after} after`,
    `${paths.blocked_after} of ${paths.path_count_after} blocked after`,
    `${paths.changed} changed`,
  ].join(", ");
}

/** A row stands for every path that shares its two outcomes, its egress and its explanation. */
function FlowPathTable({ paths }: { paths: FlowPaths }) {
  const name = useNamer();
  if (paths.groups.length === 0) return null;
  return (
    <>
      <div className="chgsim-pathscroll">
        <table className="chgsim-pathtable">
          <thead>
            <tr>
              <th>Destination</th>
              <th>Paths</th>
              <th>Egress</th>
              <th>Next hop</th>
              <th>Before</th>
              <th>After</th>
              <th>Deciding rule</th>
            </tr>
          </thead>
          <tbody>
            {paths.groups.map((group, i) => (
              <tr key={i}>
                <td>{sampleText(group.destinations, group.destination_count)}</td>
                <td>{group.path_count}</td>
                <td>{group.egress ?? "no egress interface"}</td>
                <td>{sampleText(group.next_hops, group.next_hop_count)}</td>
                <td>{name(sideText(group.before))}</td>
                <td>{name(sideText(group.after))}</td>
                <td>
                  <div>{name(group.after?.decided_by ?? group.before?.decided_by ?? "no rule")}</div>
                  {group.note && <div className="chgsim-devicemeta">{name(group.note)}</div>}
                  {mtuOutcomeLine(group) && (
                    <div className="chgsim-devicemeta">{name(mtuOutcomeLine(group) ?? "")}</div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {paths.truncated && (
        <p className="chgsim-truncated">
          {`${paths.groups.length} of ${paths.group_count} path groups`}
        </p>
      )}
    </>
  );
}

/** A flow outside the change set, or without an established comparison, has no rows and no result line. */
function FlowSection({ entry }: { entry: SimulatedFlow }) {
  const name = useNamer();
  const notEstablished = flowNotEstablished(entry);
  const paths = outsideTheChange(entry) || notEstablished ? undefined : entry.paths;
  return (
    <section className="chgsim-bucket">
      <div className="chgsim-devicename">{flowHead(entry)}</div>
      <div className="chgsim-devicemeta">{name(flowMeta(entry))}</div>
      {notEstablished && <p className="chgsim-truncated">{name(notEstablishedText(entry))}</p>}
      {paths && <FlowPathTable paths={paths} />}
      {paths && (
        <p className="chgsim-bucketempty">
          {name(resultLine(entry))}
        </p>
      )}
    </section>
  );
}

function nextHopText(hop: NextHopRecord): string {
  const kind = hop.kind === "STATIC_ROUTE" ? "static" : (hop.protocol ?? "learned");
  return `${hop.next_hop} (${kind})`;
}

function nextHopList(hops: readonly NextHopRecord[]): string {
  return hops.length ? hops.map(nextHopText).join(", ") : "none";
}

/** A predicted row's BGP attributes, each one the engine set. */
function bgpAttributes(row: PredictedBgpRow): string {
  return (
    [
      row.next_hop && `via ${row.next_hop}`,
      row.as_path?.length && `AS path ${row.as_path.join(" ")}`,
      row.local_pref != null && `local pref ${row.local_pref}`,
      row.med != null && `MED ${row.med}`,
      row.weight != null && `weight ${row.weight}`,
      row.origin && `origin ${row.origin}`,
      row.origin_mechanism && `origin mechanism ${row.origin_mechanism}`,
      row.admin != null && `admin distance ${row.admin}`,
      row.communities?.length && `communities ${row.communities.join(" ")}`,
      row.originator_ip && `originator ${row.originator_ip}`,
    ]
      .filter(Boolean)
      .join(", ") || "no attributes recorded"
  );
}

/** One BGP session that peers through a denied address. */
function bgpSessionDependencyLine(session: RoutingBgpSessionDependency, name: (text: string) => string) {
  const asns =
    session.local_asn != null && session.peer_asn != null
      ? `AS${session.local_asn} to AS${session.peer_asn}`
      : "";
  return (
    <>
      <div>{`${session.peer_ip ?? session.uid}${session.context_uid ? ` in ${name(session.context_uid)}` : ""}`}</div>
      <div className="chgsim-devicemeta">{[asns, session.uid].filter(Boolean).join(", ")}</div>
    </>
  );
}

/** The BGP sessions that peer through a denied address. */
function BgpDependencySection({ consequence }: { consequence?: RoutingConsequence }) {
  const name = useNamer();
  const sessions = consequence?.bgp_sessions_to_a_denied_address ?? [];
  if (sessions.length === 0) return null;
  return (
    <section className="chgsim-bucket">
      <div className="chgsim-buckethead">
        <h3>BGP sessions to a denied address</h3>
        <span className="chgsim-bucketcount">{sessions.length}</span>
      </div>
      {consequence?.bgp_sessions_to_a_denied_address_note && (
        <p className="chgsim-devicemeta">{name(consequence.bgp_sessions_to_a_denied_address_note)}</p>
      )}
      <ul className="chgsim-bucketlist">
        {sessions.map((session, i) => (
          <li key={i}>{bgpSessionDependencyLine(session, name)}</li>
        ))}
      </ul>
    </section>
  );
}

/** The line for a withdrawal walk that a limit stopped. */
function walkLimitLine(walk: WithdrawalWalk): string | null {
  if (walk.complete !== false) return null;
  const limits = walk.limits ?? [];
  const cut: string[] = [];
  if (limits.includes("depth")) {
    cut.push(
      `the depth limit ${walk.depth ?? 1} with ${walk.prefixes_not_followed_at_the_depth_limit ?? 0} prefixes not followed`,
    );
  }
  if (limits.includes("site_boundary")) {
    cut.push(
      `the site boundary with ${walk.prefixes_not_followed_at_the_site_boundary ?? 0} prefixes outside the selected sites not followed`,
    );
  }
  if (cut.length === 0) return null;
  return `Walk stopped by ${cut.join(" and ")}`;
}

function WithdrawalWalkSection({ walk, scope }: { walk?: WithdrawalWalk; scope?: WithdrawalSiteScope }) {
  const levels = walk?.levels ?? [];
  const limitLine = walk ? walkLimitLine(walk) : null;
  if (levels.length === 0 && !limitLine && !scope) return null;
  return (
    <section className="chgsim-bucket">
      <div className="chgsim-buckethead">
        <h3>Withdrawal walk</h3>
        {walk?.levels_walked != null && (
          <span className="chgsim-bucketcount">{walk.levels_walked}</span>
        )}
      </div>
      {scope?.sites_resolved?.length ? (
        <p className="chgsim-bucketempty">
          {`Limited to ${scope.sites_resolved.join(", ")}`}
          {scope.sites_not_found?.length
            ? `, with ${scope.sites_not_found.join(", ")} not found`
            : ""}
        </p>
      ) : null}
      {levels.length > 0 && (
        <ul className="chgsim-bucketlist">
          {levels.map((level) => (
            <li key={level.level}>
              <div>{`Level ${level.level}`}</div>
              <div className="chgsim-devicemeta">
                {`${level.prefix_count} prefixes across ${level.vrf_count} VRFs, ${level.prefixes_with_no_next_hop_left} left with no recorded next hop, ${level.withdrawn_route_edge_count} route edges withdrawn`}
              </div>
              {level.sample?.length ? (
                <div className="chgsim-devicemeta">
                  {`for example ${level.sample.join(", ")}`}
                  {level.sample_truncated ? ` and ${level.prefix_count - level.sample.length} more` : ""}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {limitLine && <p className="chgsim-truncated">{limitLine}</p>}
    </section>
  );
}

function PolicyChangePrediction({ policy }: { policy: SimulatePolicyChangeResult }) {
  const name = useNamer();
  const withdrawal = policy.routing_consequence?.next_hop_withdrawal;
  const notEstablished = resultsNotEstablished(policy);
  const meta = [
    `${policy.flow_count} ${policy.flow_count === 1 ? "flow" : "flows"}`,
    `${policy.results_changed} with a changed result`,
    notEstablished > 0 ? `${notEstablished} with a comparison not established` : "",
    policy.path_count_after != null
      ? `${policy.paths_blocked_after ?? 0} of ${policy.path_count_after} paths blocked${
          notEstablished > 0 ? ` with the ${notEstablished === 1 ? "flow" : "flows"} not established` : ""
        }`
      : "",
    policy.paths_changed != null ? `${policy.paths_changed} paths changed` : "",
    policy.changed_devices?.length
      ? `on ${policy.changed_devices.map((uid) => policy.changed_device_hostnames?.[uid] ?? name(uid)).join(", ")}`
      : "",
  ].filter(Boolean);
  return (
    <div className="chgsim-panebody">
      <div className="chgsim-device">
        <div className="chgsim-devicename">Proposed policy change</div>
        <div className="chgsim-devicemeta">{meta.join(", ")}</div>
        <ExportControl policy={policy} />
      </div>
      {policy.flows_derived && <p className="chgsim-bucketempty">{name(policy.flows_derived)}</p>}
      {policy.flows_derived_truncated && (
        <p className="chgsim-truncated">
          {`${policy.flows_derived_count ?? policy.flow_count} flows traced, ${policy.flows_derived_not_traced ?? 0} candidates not traced`}
        </p>
      )}
      {(policy.flows ?? []).map((entry, i) => (
        <FlowSection key={i} entry={entry} />
      ))}
      {policy.routing_consequence?.headline && (
        <section className="chgsim-bucket">
          <div className="chgsim-buckethead">
            <h3>Routing consequence</h3>
          </div>
          <p className="chgsim-bucketempty">{name(policy.routing_consequence.headline)}</p>
        </section>
      )}
      <WithdrawalWalkSection
        walk={policy.routing_consequence?.walk}
        scope={policy.routing_consequence?.site_scope}
      />
      {withdrawal?.vrfs?.map((vrf) => (
        <ListSection
          key={vrf.context_uid}
          title={`Routes through a denied next hop in ${name(vrf.context_uid)}`}
          items={vrf.prefixes ?? []}
          count={vrf.prefix_count}
          truncated={vrf.truncated}
          render={(p) => (
            <>
              <div>{p.prefix}</div>
              <div className="chgsim-devicemeta">
                next hops recorded before: {nextHopList(p.next_hops_before ?? [])}
              </div>
              <div className="chgsim-devicemeta">
                next hops remaining after: {nextHopList(p.next_hops_after ?? [])}
              </div>
            </>
          )}
        />
      ))}
      {withdrawal?.truncation && <p className="chgsim-truncated">{name(withdrawal.truncation)}</p>}
      <BgpDependencySection consequence={policy.routing_consequence} />
      <ListSection
        title="BGP best path changed"
        items={policy.routing_consequence?.predicted_rows_changed ?? []}
        count={policy.routing_consequence?.predicted_changed_count}
        render={(row) => (
          <>
            <div>{`${row.prefix} in ${name(row.context_uid)}`}</div>
            <div className="chgsim-devicemeta">before: {bgpAttributes(row.before)}</div>
            <div className="chgsim-devicemeta">after: {bgpAttributes(row.after)}</div>
          </>
        )}
      />
    </div>
  );
}

/** `unreadable` names the tool of the newest prediction call whose result could not be read. */
export function PredictedPane({
  result,
  unreadable = null,
}: {
  result: PredictedResult | null;
  unreadable?: string | null;
}) {
  const name = useNamer();
  const modelErrors = result ? modelErrorLines(result).map(name) : [];
  const snapshot = resultSnapshot(result);
  return (
    <section className="chgsim-pane" aria-label="Predicted pane">
      <header className="chgsim-panehead">
        <h2>Predicted</h2>
      </header>
      {unreadable && (
        <p className="chgsim-empty">{`${unreadable} result could not be read`}</p>
      )}
      {!result ? (
        !unreadable && (
          <p className="chgsim-empty">no prediction</p>
        )
      ) : (
        <>
          <div className="chgsim-strip">
            <p>
              Snapshot {snapshot ? formatSnapshotDate(Number(snapshot)) : "not known"}
            </p>
            {modelErrors.length > 0 && (
              <ul className="chgsim-modelgaps">
                {modelErrors.map((gap, i) => (
                  <li key={i}>{gap}</li>
                ))}
              </ul>
            )}
          </div>
          {result.tool === "assess_impact" && <ImpactPrediction impact={result.impact} />}
          {result.tool === "predict_routes" && <RoutePrediction routes={result.routes} />}
          {result.tool === "simulate_policy_change" && (
            <PolicyChangePrediction policy={result.policy} />
          )}
        </>
      )}
    </section>
  );
}
