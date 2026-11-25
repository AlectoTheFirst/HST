/**
 * Import this module only from code that is itself loaded lazily.
 */

import ELK, { type ELK as ElkEngine, type ElkNode } from "elkjs/lib/elk-api";
import ElkWorker from "elkjs/lib/elk-worker.min.js?worker";

let engine: ElkEngine | null = null;

export function layout(graph: ElkNode): Promise<ElkNode> {
  engine ??= new ELK({ workerFactory: () => new ElkWorker() });
  return engine.layout(graph);
}
