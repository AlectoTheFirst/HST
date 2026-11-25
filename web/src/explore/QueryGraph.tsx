/** The result card owns the view graph (ResultCard.tsx). */

import { useQuery } from "@tanstack/react-query";
import { exploreApi } from "../api/explore";
import type { GraphNode, ResultGraph } from "../api/types";
import GraphView from "./GraphView";
import { Group, message } from "./SearchView";
import "./graphview.css";

export default function QueryGraph({ graph, onGraph, onOpen, objectPanel }: {
  /** The view graph of the result card. */
  graph: ResultGraph;
  /** Adds a loaded payload to the view graph. */
  onGraph: (payload: ResultGraph) => void;
  onOpen: (uid: string) => void;
  /** Rendered above the relationships of the selected node. */
  objectPanel?: (node: { labels: string[]; properties: Record<string, unknown> }) => React.ReactNode;
}) {
  const panel = (node: GraphNode) =>
    typeof node.properties.uid === "string" ? (
      <>
        {objectPanel?.({ labels: node.labels, properties: node.properties })}
        <Relationships key={node.properties.uid} uid={node.properties.uid} onOpen={onOpen} onGraph={onGraph} />
      </>
    ) : null;
  return <GraphView graph={graph} onOpen={onOpen} grows selectedPanel={panel} />;
}

function Relationships({ uid, onOpen, onGraph }: {
  uid: string; onOpen: (uid: string) => void; onGraph: (graph: ResultGraph) => void;
}) {
  const detail = useQuery({ queryKey: ["explore", "node", uid], queryFn: () => exploreApi.node(uid) });
  return (
    <section className="gv-expand" aria-label="Relationships">
      <h3 className="eyebrow">Relationships</h3>
      {detail.isPending && <p className="hint" role="status">Loading</p>}
      {detail.isError && <div className="banner err"><div className="sub">{message(detail.error)}</div></div>}
      {detail.data && detail.data.neighbors.length === 0 && (
        <p className="hint">No relationships</p>
      )}
      {detail.data && detail.data.neighbors.length > 0 && (
        <ul className="xb-groups">
          {detail.data.neighbors.map((group) => (
            <Group key={`${group.type}-${group.direction}-${group.label}`} uid={uid} group={group} onOpen={onOpen} onGraph={onGraph} />
          ))}
        </ul>
      )}
    </section>
  );
}
