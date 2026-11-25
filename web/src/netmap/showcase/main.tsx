import "../../theme.css";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRoot } from "react-dom/client";
import type { TopologyModel } from "../../api/types";
import { DEMO_MADRID } from "../fixtures/demoMadrid";
import { DEMO_OFFICE } from "../fixtures/demoOffice";
import { HOME_SITE } from "../fixtures/homeSite";
import { Diagram } from "../NetworkMapPage";
import type { Layer } from "../overlays";

// A site diagram on a fixture in the dev server (`npm run dev`, then
// /netmap-showcase.html). `model` is home, demo or madrid, `layer` phys, l2 or l3, `vid` and
// `domain` the picks, `theme` the palette, `options=1` opens the Options drawer, and `moved`, `x` and `y`
// a stored position of one device or bar.
const q = new URLSearchParams(location.search);
document.documentElement.dataset.theme = q.get("theme") ?? "light";
const models: Record<string, TopologyModel> = {
  home: HOME_SITE,
  demo: DEMO_OFFICE,
  madrid: DEMO_MADRID,
};
const picked = models[q.get("model") ?? "home"] ?? HOME_SITE;
// `parallel=1` draws a second cable beside each peer-link
const model: TopologyModel =
  q.get("parallel") === "1"
    ? {
        ...picked,
        cables: [
          ...picked.cables,
          ...picked.cables
            .filter((c) => c.lateral)
            .map((c) => ({ ...c, id: `${c.id}:2`, from: { ...c.from, port: `${c.from.port}.2` }, to: { ...c.to, port: `${c.to.port}.2` } })),
        ],
      }
    : picked;
const moved = q.get("moved");
const at = moved
  ? { [moved]: { x: Number(q.get("x") ?? 0), y: Number(q.get("y") ?? 0) } }
  : {};

createRoot(document.getElementById("root")!).render(
  <QueryClientProvider client={new QueryClient()}>
    <div className="nm-page" style={{ height: "100vh" }}>
      <Diagram
        model={model}
        site="showcase"
        stored={{
          scope: "",
          positions: at,
          revision: 0,
          updated_by: null,
          updated_at: null,
        }}
        canWrite={true}
        initial={{
          layer: (q.get("layer") as Layer | null) ?? "phys",
          vid: q.get("vid") ? Number(q.get("vid")) : null,
          domain: q.get("domain"),
          segments: q.get("segments") !== "0",
          clients: q.get("clients") === "1",
        }}
        flows={null}
        onFlows={() => {}}
        onNotice={() => {}}
        onReset={() => {}}
      />
    </div>
  </QueryClientProvider>,
);
if (q.get("options") === "1") {
  window.setTimeout(
    () =>
      [...document.querySelectorAll<HTMLButtonElement>("button")].find((el) => el.textContent === "Options")?.click(),
    300,
  );
}
