/** The Baseline pane shows what the pinned snapshot records. */

import { formatSnapshotDate } from "../flowdesk/SnapshotPicker";
import type {
  AssessImpactResult,
  BaselineResult,
  ResolveAddressResult,
} from "./assessImpact";
import { resultSnapshot } from "./assessImpact";
import { useNamer } from "../shell/deviceNames";
import { BucketSection, DeviceIdentity, ListSection } from "./Buckets";
import "./changesim.css";

function ImpactBaseline({ impact }: { impact: AssessImpactResult }) {
  return (
    <div className="chgsim-panebody">
      <DeviceIdentity device={impact.device} />
      <BucketSection
        title="Gateway prefixes"
        bucket={impact.gateway_prefixes}
        render={(p) => `${p.cidr ?? p.uid}${p.kind ? ` (${p.kind})` : ""}`}
      />
      <BucketSection
        title="Attached endpoints"
        bucket={impact.attached_endpoints}
        render={(e) => e.name ?? e.uid}
      />
      <BucketSection
        title="Redundancy membership"
        bucket={impact.redundancy_groups}
        render={(g) => `${g.name ?? g.uid}${g.kind ? ` (${g.kind})` : ""}${g.role ? `, ${g.role}` : ""}`}
      />
    </div>
  );
}

function AddressBaseline({ address }: { address: ResolveAddressResult }) {
  const name = useNamer();
  // The tool caps each section at limit_per_section rows without a truncation flag.
  const cap = address.limit_per_section;
  const capped = (n: number) => typeof cap === "number" && cap > 0 && n >= cap;
  const l3doms = [...new Set(address.ip_nodes.map((n) => n.l3dom).filter((d): d is string => !!d))];
  return (
    <div className="chgsim-panebody">
      <div className="chgsim-device">
        <div className="chgsim-devicename">{address.address}</div>
        {l3doms.length > 0 && <div className="chgsim-devicemeta">{l3doms.join(", ")}</div>}
      </div>
      <ListSection
        title="Address nodes"
        items={address.ip_nodes}
        truncated={capped(address.ip_nodes.length)}
        render={(n) =>
          `${n.uid}${n.l3dom ? ` in ${n.l3dom}` : ""}${n.anchor ? `, anchor ${name(n.anchor)}` : ""}`
        }
      />
      <ListSection
        title="Endpoints"
        items={address.endpoints}
        truncated={capped(address.endpoints.length)}
        render={(e) => {
          const label = `${e.name ?? e.mac ?? e.uid}${e.kind ? ` (${e.kind})` : ""}`;
          const attached = e.attached
            .map((a) => a.name ?? a.uid)
            .filter((a) => !!a)
            .join(", ");
          const bds = e.bridge_domains.map((b) => b.name ?? b.uid).join(", ");
          return [label, attached && `attached to ${attached}`, bds && `bridge domain ${bds}`]
            .filter(Boolean)
            .join(", ");
        }}
      />
      <ListSection
        title="Interfaces"
        items={address.interfaces}
        truncated={capped(address.interfaces.length)}
        render={(i) => {
          const device = i.device_hostname ?? (i.device_uid ? name(i.device_uid) : null);
          const label = `${i.name ?? i.uid}${i.kind ? ` (${i.kind})` : ""}`;
          return device ? `${device} ${label}` : label;
        }}
      />
      <ListSection
        title="BGP sessions"
        items={address.bgp_sessions}
        truncated={capped(address.bgp_sessions.length)}
        render={(s) => {
          const peer = `peer ${s.peer_ip ?? "not recorded"}${s.peer_asn != null ? ` (AS${s.peer_asn})` : ""}`;
          const vrf = s.vrf_name ?? s.vrf_uid;
          const policies = [
            s.import_policy_name && `import ${s.import_policy_name}`,
            s.export_policy_name && `export ${s.export_policy_name}`,
          ]
            .filter(Boolean)
            .join(", ");
          return [vrf ? `${peer} in ${vrf}` : peer, policies].filter(Boolean).join(", ");
        }}
      />
      <ListSection
        title="Next-hop routes"
        items={address.next_hop_routes}
        truncated={capped(address.next_hop_routes.length)}
        render={(r) => {
          const prefix = r.prefix ?? r.prefix_uid ?? "prefix not recorded";
          const vrf = r.vrf_name ?? r.vrf_uid;
          const proto = r.protocol ?? r.kind;
          return [
            `${prefix} via this address`,
            proto && `(${proto})`,
            vrf && `in ${vrf}`,
            r.interface && `out ${r.interface}`,
          ]
            .filter(Boolean)
            .join(" ");
        }}
      />
    </div>
  );
}

export function BaselinePane({ result }: { result: BaselineResult | null }) {
  const snapshot = resultSnapshot(result);
  return (
    <section className="chgsim-pane" aria-label="Baseline pane">
      <header className="chgsim-panehead">
        <h2>Baseline</h2>
        <span className="chgsim-panets">
          {result ? (snapshot ? formatSnapshotDate(Number(snapshot)) : "no run pinned") : "no assessment"}
        </span>
      </header>
      {!result ? null : result.tool === "assess_impact" ? (
        <ImpactBaseline impact={result.impact} />
      ) : (
        <AddressBaseline address={result.address} />
      )}
    </section>
  );
}
