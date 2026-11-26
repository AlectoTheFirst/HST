import { lazy, Suspense, useMemo, useState } from "react";
import { memberSource, memberStateOf, structureGraph } from "./structureModel";
import type { BusinessApplicationDefinition, FlowCheck, ResolvedApplication } from "./types";

export {
  READ_ONLY,
  memberSource,
  structureElements,
  structureGraph,
  structureLayout,
  type StructureEdge,
  type StructureGraphModel,
  type StructureNode,
} from "./structureModel";

const StructureGraph = lazy(() => import("./ApplicationStructureGraph"));

/**
 * The structure view of a definition the server normalized, in list or graph
 * mode. The list shows services with their component roles, groups with
 * their members, and the connections. With a resolution, each resolved member
 * shows its state and each connection its readiness at the resolution's
 * snapshot. The graph draws the groups and connections (`StructureGraph`),
 * with the results of `flows` when a flow check ran.
 */
export function ApplicationStructure({
  definition,
  resolution,
  flows,
}: {
  definition: BusinessApplicationDefinition;
  resolution?: ResolvedApplication | null;
  flows?: FlowCheck[] | null;
}) {
  const [mode, setMode] = useState<"list" | "graph">("list");
  const graph = useMemo(
    () => structureGraph(definition, resolution, flows),
    [definition, resolution, flows],
  );
  const readiness = new Map(
    (resolution?.connections ?? []).map((item) => [item.id, item.readiness] as const),
  );
  const memberState = memberStateOf(resolution);
  return (
    <section className="application-structure" aria-label="Structure">
      <div className="application-structure-mode" role="group" aria-label="Structure view">
        <button type="button" aria-pressed={mode === "list"} onClick={() => setMode("list")}>
          List
        </button>
        <button type="button" aria-pressed={mode === "graph"} onClick={() => setMode("graph")}>
          Graph
        </button>
      </div>
      {mode === "graph" ? (
        <Suspense fallback={<p>Loading the graph</p>}>
          <StructureGraph graph={graph} />
        </Suspense>
      ) : (
        <>
          <h4>Services</h4>
          {definition.services.length === 0 ? (
            <p>No services</p>
          ) : (
            <ul>
              {definition.services.map((service) => (
                <li key={service.id}>
                  <strong>{service.name}</strong> <code>{service.id}</code>
                  {service.component_roles.length > 0 &&
                    `: ${service.component_roles.map((role) => `${role.group_id} as ${role.role}`).join(", ")}`}
                </li>
              ))}
            </ul>
          )}
          <h4>Component groups</h4>
          {definition.groups.length === 0 ? (
            <p>No groups</p>
          ) : (
            definition.groups.map((group) => (
              <article className="application-row" key={group.id}>
                <div>
                  <strong>{group.name}</strong>
                  <code>{group.id}</code>
                </div>
                <ul>
                  {group.members.map((member) => {
                    const state = memberState(group.id, member.id);
                    return (
                      <li key={member.id}>
                        <strong>{member.name ?? member.id}</strong>: {memberSource(member)}
                        {state && ` (${state})`}
                      </li>
                    );
                  })}
                </ul>
              </article>
            ))
          )}
          <h4>Connections</h4>
          {definition.connections.length === 0 ? (
            <p>No connections</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th scope="col">Connection</th>
                  <th scope="col">Source</th>
                  <th scope="col">Destination</th>
                  <th scope="col">Protocol and ports</th>
                  <th scope="col">Success</th>
                  <th scope="col">Readiness</th>
                </tr>
              </thead>
              <tbody>
                {definition.connections.map((connection) => (
                  <tr key={connection.id}>
                    <td>
                      {connection.name} <code>{connection.id}</code>
                    </td>
                    <td>{connection.source}</td>
                    <td>{connection.destination}</td>
                    <td>
                      {[
                        connection.protocol ?? "protocol unspecified",
                        connection.destination_ports?.length
                          ? `ports ${connection.destination_ports.join(", ")}`
                          : "ports unspecified",
                      ].join(", ")}
                    </td>
                    <td>{connection.success}</td>
                    <td>{readiness.get(connection.id) ?? "not resolved"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </section>
  );
}
