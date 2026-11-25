import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import fcose from "cytoscape-fcose";

/** Import this module only from code that is loaded lazily. */
let registered = false;

/** Cytoscape with the fcose and dagre layouts registered. */
export function withLayouts(): typeof cytoscape {
  if (!registered) {
    cytoscape.use(fcose);
    cytoscape.use(dagre);
    registered = true;
  }
  return cytoscape;
}
