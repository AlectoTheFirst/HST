import { describe, expect, it } from "vitest";

import { clientToUser, meetScale } from "./useCanvas";

// a 2:1 view, as the estate and the site pages draw it
const VIEW = { x: 0, y: 0, w: 200, h: 100 };

describe("meetScale", () => {
  it("scales by the height and centres the picture in a pane wider than the view", () => {
    // 2000 x 600 px: the picture is 1200 px wide, with a 400 px band each side
    expect(meetScale(VIEW, { left: 0, top: 0, width: 2000, height: 600 })).toEqual({ s: 6, ox: 400, oy: 0 });
  });

  it("scales by the width and centres the picture in a pane narrower than the view", () => {
    // 400 x 600 px: the picture is 200 px high, with a 200 px band above and below
    expect(meetScale(VIEW, { left: 0, top: 0, width: 400, height: 600 })).toEqual({ s: 2, ox: 0, oy: 200 });
  });

  it("has no bands when the pane has the view's shape", () => {
    expect(meetScale(VIEW, { left: 0, top: 0, width: 800, height: 400 })).toEqual({ s: 4, ox: 0, oy: 0 });
  });
});

describe("clientToUser", () => {
  const wide = { left: 10, top: 20, width: 2000, height: 600 };
  const narrow = { left: 10, top: 20, width: 400, height: 600 };

  it("maps the picture's corners, not the pane's, to the view's corners in a wide pane", () => {
    expect(clientToUser(VIEW, wide, 10 + 400, 20)).toEqual({ x: 0, y: 0 });
    expect(clientToUser(VIEW, wide, 10 + 1600, 20 + 600)).toEqual({ x: 200, y: 100 });
  });

  it("maps the picture's corners to the view's corners in a narrow pane", () => {
    expect(clientToUser(VIEW, narrow, 10, 20 + 200)).toEqual({ x: 0, y: 0 });
    expect(clientToUser(VIEW, narrow, 10 + 400, 20 + 400)).toEqual({ x: 200, y: 100 });
  });

  it("maps the pane's centre to the view's centre in both shapes", () => {
    expect(clientToUser(VIEW, wide, 10 + 1000, 20 + 300)).toEqual({ x: 100, y: 50 });
    expect(clientToUser(VIEW, narrow, 10 + 200, 20 + 300)).toEqual({ x: 100, y: 50 });
  });

  it("moves one user unit per s px on both axes, so a pan follows the pointer", () => {
    const { s } = meetScale(VIEW, wide);
    const a = clientToUser(VIEW, wide, 900, 300);
    const b = clientToUser(VIEW, wide, 900 + 60, 300 + 60);
    expect(b.x - a.x).toBeCloseTo(60 / s);
    expect(b.y - a.y).toBeCloseTo(60 / s);
  });

  it("keeps the view's offset", () => {
    const moved = { ...VIEW, x: -50, y: 30 };
    expect(clientToUser(moved, wide, 10 + 400, 20)).toEqual({ x: -50, y: 30 });
  });
});
