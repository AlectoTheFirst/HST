import "../../theme.css";
import { createRoot } from "react-dom/client";
import HstMapPage from "../HstMapPage";
import { createThreeRenderer } from "../render/three";
import { FakeSource } from "../test/runs";
import { showcase } from "../test/showcase";

// `theme` sets the palette, `find` selects a device, `wheel` zooms in by steps.
const q = new URLSearchParams(location.search);
document.documentElement.dataset.theme = q.get("theme") ?? "light";
createRoot(document.getElementById("root")!).render(
  <HstMapPage source={new FakeSource([showcase(), showcase()])} events={null} renderer={async (c) => createThreeRenderer(c)} />,
);
window.setTimeout(() => {
  const canvas = document.querySelector(".hst-map-canvas");
  if (!canvas) return;
  const box = canvas.getBoundingClientRect();
  for (let i = 0; i < Number(q.get("wheel") ?? 0); i++) {
    canvas.dispatchEvent(new WheelEvent("wheel", { deltaY: -120, clientX: box.left + box.width / 2, clientY: box.top + box.height / 2, bubbles: true, cancelable: true }));
  }
  const find = q.get("find");
  const input = document.querySelector<HTMLInputElement>('input[type="search"]');
  if (find && input) {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, find);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  }
}, 900);
