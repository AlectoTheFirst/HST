import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup, configure } from "@testing-library/react";
import { setOnUnauthorized } from "../api/client";

// findBy* and waitFor wait up to 5000 ms.
configure({ asyncUtilTimeout: 5000 });

/**
 * jsdom's `getContext("2d")` returns null.
 */
function stubContext2d(): CanvasRenderingContext2D {
  const state: Record<string, unknown> = {
    canvas: null,
    measureText: () => ({ width: 0 }),
    getTransform: () => ({ a: 1, b: 0, c: 0, d: 1, e: 0, f: 0 }),
    createLinearGradient: () => ({ addColorStop: () => {} }),
    createRadialGradient: () => ({ addColorStop: () => {} }),
    createPattern: () => null,
    getImageData: () => ({ data: new Uint8ClampedArray(4), width: 1, height: 1 }),
  };
  return new Proxy(state, {
    // an unset property is a drawing call the renderer makes and ignores; one
    // it assigned (lineWidth, font, fillStyle) reads back as it was set
    get: (target, prop: string) => (prop in target ? target[prop] : () => undefined),
    set: (target, prop: string, value) => {
      target[prop] = value;
      return true;
    },
  }) as unknown as CanvasRenderingContext2D;
}

// A file with `@vitest-environment node` gets this setup too and has no DOM.
if (typeof HTMLCanvasElement !== "undefined") {
  HTMLCanvasElement.prototype.getContext = function getContext(kind: string) {
    return kind === "2d" ? stubContext2d() : null;
  } as HTMLCanvasElement["getContext"];
}

afterEach(() => {
  cleanup();
  setOnUnauthorized(null);
  // jsdom keeps one localStorage for every test of a file.
  try {
    window.localStorage?.clear();
  } catch {
    // no storage on this origin
  }
});
