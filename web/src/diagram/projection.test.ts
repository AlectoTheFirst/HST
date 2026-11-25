import { describe, expect, it } from "vitest";
import { project, WORLD_H, WORLD_W } from "./projection";
import { landPath } from "./world";

describe("projection", () => {
  it("maps the world onto a 2:1 rectangle with north up", () => {
    expect(project(90, -180)).toEqual({ x: 0, y: 0 });
    expect(project(-90, 180)).toEqual({ x: WORLD_W, y: WORLD_H });
    expect(project(0, 0)).toEqual({ x: WORLD_W / 2, y: WORLD_H / 2 });
  });

  it("projects land rings into closed subpaths", () => {
    expect(landPath([])).toBe("");
    expect(landPath([[[0, 0], [10, 0], [10, 10]]])).toBe("M 720.0 360.0 L 760.0 360.0 L 760.0 320.0 Z");
  });
});
