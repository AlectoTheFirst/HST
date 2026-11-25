import * as THREE from "three";
import { RoundedBoxGeometry } from "three/examples/jsm/geometries/RoundedBoxGeometry.js";
import type { LineMaterial } from "three/examples/jsm/lines/LineMaterial.js";
import { mergeGeometries } from "three/examples/jsm/utils/BufferGeometryUtils.js";
import type { Shape } from "./models";

/** The brightness of a model at its base and at its top. */
const BASE_SHADE = 0.72;
const TOP_SHADE = 1.12;

/** Gives `g` vertex colours that brighten from the base (y = 0) to the top (y = 1). */
function gradient(g: THREE.BufferGeometry): THREE.BufferGeometry {
  const pos = g.getAttribute("position");
  const colors = new Float32Array(pos.count * 3);
  for (let i = 0; i < pos.count; i++) {
    const y = Math.min(1, Math.max(0, pos.getY(i)));
    colors.fill(BASE_SHADE + (TOP_SHADE - BASE_SHADE) * y, i * 3, i * 3 + 3);
  }
  g.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  return g;
}

/** A cylinder of radius 0.5 and height 1 with rounded rims, its base centred at (0.5, 0, 0.5). */
function roundedCylinder(bevel: number): THREE.BufferGeometry {
  const points: THREE.Vector2[] = [new THREE.Vector2(0, 0)];
  const arc = (cx: number, cy: number, from: number, to: number) => {
    for (let i = 0; i <= 6; i++) {
      const a = from + ((to - from) * i) / 6;
      points.push(new THREE.Vector2(cx + bevel * Math.cos(a), cy + bevel * Math.sin(a)));
    }
  };
  arc(0.5 - bevel, bevel, -Math.PI / 2, 0);
  arc(0.5 - bevel, 1 - bevel, 0, Math.PI / 2);
  points.push(new THREE.Vector2(0, 1));
  return new THREE.LatheGeometry(points, 56).translate(0.5, 0, 0.5);
}

/** The unit geometry of a model shape: x and z in [0, 1], y in [0, 1], with the base-to-top shade. */
export function modelGeometry(shape: Shape): THREE.BufferGeometry {
  switch (shape) {
    case "box":
      return gradient(new RoundedBoxGeometry(1, 1, 1, 4, 0.16).translate(0.5, 0.5, 0.5));
    case "rack":
      return gradient(new RoundedBoxGeometry(1, 1, 1, 3, 0.05).translate(0.5, 0.5, 0.5));
    case "cylinder":
      return gradient(roundedCylinder(0.14));
    case "dome":
      return gradient(new THREE.SphereGeometry(0.5, 40, 16, 0, Math.PI * 2, 0, Math.PI / 2).scale(1, 2, 1).translate(0.5, 0, 0.5));
    case "cloud": {
      const puffs: [number, number, number, number][] = [
        [0.28, 0.3, 0.5, 0.24],
        [0.52, 0.45, 0.48, 0.32],
        [0.75, 0.32, 0.52, 0.23],
        [0.5, 0.28, 0.28, 0.24],
        [0.5, 0.28, 0.72, 0.24],
      ];
      return gradient(mergeGeometries(puffs.map(([x, y, z, r]) => new THREE.SphereGeometry(r, 28, 18).translate(x, y, z))));
    }
  }
}

function canvas(size: number, draw: (g: CanvasRenderingContext2D) => void): THREE.CanvasTexture {
  const c = document.createElement("canvas");
  c.width = size;
  c.height = size;
  const g = c.getContext("2d");
  if (g) draw(g);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

/** White bricks with grey mortar, tinted by the instance colour. */
export function brickTexture(): THREE.Texture {
  const t = canvas(256, (g) => {
    g.fillStyle = "#9da3ab";
    g.fillRect(0, 0, 256, 256);
    g.fillStyle = "#ffffff";
    const rows = 6;
    const h = 256 / rows;
    for (let r = 0; r < rows; r++) {
      const shift = r % 2 ? 32 : 0;
      for (let x = -64; x < 256; x += 64) g.fillRect(x + shift + 3, r * h + 3, 58, h - 6);
    }
  });
  t.wrapS = t.wrapT = THREE.RepeatWrapping;
  return t;
}

/** Rack fronts: white panels with dark slot lines, tinted by the instance colour. */
export function rackTexture(): THREE.Texture {
  return canvas(256, (g) => {
    g.fillStyle = "#ffffff";
    g.fillRect(0, 0, 256, 256);
    g.fillStyle = "#7b8796";
    for (let y = 14; y < 256; y += 26) g.fillRect(24, y, 208, 5);
    g.fillStyle = "#d8f0ff";
    for (let y = 14; y < 256; y += 26) g.fillRect(200, y - 1, 12, 7);
  });
}

/** A soft round shadow, dark at the centre and clear at the rim. */
export function shadowTexture(): THREE.Texture {
  return canvas(128, (g) => {
    const r = g.createRadialGradient(64, 64, 4, 64, 64, 64);
    r.addColorStop(0, "rgba(0,0,0,0.55)");
    r.addColorStop(0.5, "rgba(0,0,0,0.22)");
    r.addColorStop(1, "rgba(0,0,0,0)");
    g.fillStyle = r;
    g.fillRect(0, 0, 128, 128);
  });
}

export function symbolTexture(image: HTMLImageElement, size: number): THREE.Texture {
  const t = canvas(size, (g) => {
    g.shadowColor = "rgba(0,0,0,0.45)";
    g.shadowBlur = size / 24;
    g.shadowOffsetY = size / 48;
    g.drawImage(image, size * 0.06, size * 0.06, size * 0.88, size * 0.88);
  });
  t.anisotropy = 8;
  return t;
}

/** A backbone node: a ring of `rim` around a white centre, both on the top of a low disc. */
export function nodeGeometry(rim: THREE.Color): THREE.BufferGeometry {
  const paint = (g: THREE.BufferGeometry, c: THREE.Color) => {
    const n = g.getAttribute("position").count;
    const colors = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) colors.set([c.r, c.g, c.b], i * 3);
    g.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    return g;
  };
  const outer = paint(new THREE.CylinderGeometry(0.5, 0.5, 1, 32).translate(0.5, 0.5, 0.5), rim);
  const inner = paint(new THREE.CylinderGeometry(0.28, 0.28, 0.1, 32).translate(0.5, 1.02, 0.5), new THREE.Color(1, 1, 1));
  return mergeGeometries([outer.toNonIndexed(), inner.toNonIndexed()]);
}

/**
 * Soft rounded areas. Per instance: `aRect` (u, v, w, h), `aTint` (linear rgb), `aKind` (0 plate, 1 band) and
 * `aSel` (1 when selected). The fill brightens toward the centre, the edge is a thin line of constant pixel
 * width, and a selected area glows outside its edge.
 */
export function areaMaterial(): THREE.ShaderMaterial {
  return new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    uniforms: { uOpacity: { value: 1 } },
    vertexShader: /* glsl */ `
      attribute vec4 aRect;
      attribute vec3 aTint;
      attribute float aKind;
      attribute float aSel;
      varying vec2 vLocal;
      varying vec2 vHalf;
      varying vec3 vTint;
      varying float vKind;
      varying float vSel;
      void main() {
        float pad = 0.08 * max(aRect.z, aRect.w) + 1.0;
        vec2 size = aRect.zw + 2.0 * pad;
        vec2 local = position.xz * size - pad;
        vLocal = local - aRect.zw * 0.5;
        vHalf = aRect.zw * 0.5;
        vTint = aTint;
        vKind = aKind;
        vSel = aSel;
        vec3 world = vec3(aRect.x + local.x, position.y, aRect.y + local.y);
        gl_Position = projectionMatrix * viewMatrix * vec4(world, 1.0);
      }`,
    fragmentShader: /* glsl */ `
      uniform float uOpacity;
      varying vec2 vLocal;
      varying vec2 vHalf;
      varying vec3 vTint;
      varying float vKind;
      varying float vSel;
      float box(vec2 p, vec2 b, float r) {
        vec2 q = abs(p) - b + r;
        return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r;
      }
      void main() {
        float r = min(min(vHalf.x, vHalf.y) * 0.22, 4.0);
        float d = box(vLocal, vHalf, r);
        float px = fwidth(d);
        float inside = 1.0 - smoothstep(-px, px, d);
        float depth = clamp(-d / max(min(vHalf.x, vHalf.y), 1e-3), 0.0, 1.0);
        float region = step(1.5, vKind);
        float band = step(0.5, vKind) * (1.0 - region);
        float fill = mix(mix(0.07, 0.04, depth), mix(0.30, 0.16, smoothstep(0.0, 0.8, depth)), band);
        fill = mix(fill, mix(0.11, 0.06, depth), region);
        float edge = (1.0 - smoothstep(0.0, 1.6 * px, abs(d))) * mix(mix(0.28, 0.75, band), 0.6, region);
        float glow = (1.0 - smoothstep(0.0, 1.0, max(d, 0.0) / (6.0 * px + 0.6))) * mix(mix(0.10, 0.22, band), 0.18, region);
        glow = max(glow, vSel * (1.0 - smoothstep(0.0, 1.0, max(d, 0.0) / (14.0 * px + 1.0))) * 0.55);
        float alpha = max(max(fill * inside, edge), glow * step(0.0, d));
        gl_FragColor = vec4(vTint, alpha * uOpacity);
        #include <colorspace_fragment>
      }`,
  });
}

/** A faint grid on the ground plane, at a spacing the caller sets per zoom, fading out with distance. */
export function groundMaterial(): THREE.ShaderMaterial {
  return new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    uniforms: {
      uColor: { value: new THREE.Color() },
      uSpacing: { value: 4 },
      uCenter: { value: new THREE.Vector2() },
      uReach: { value: 200 },
      uOpacity: { value: 1 },
    },
    vertexShader: /* glsl */ `
      varying vec2 vWorld;
      void main() {
        vec4 w = modelMatrix * vec4(position, 1.0);
        vWorld = w.xz;
        gl_Position = projectionMatrix * viewMatrix * w;
      }`,
    fragmentShader: /* glsl */ `
      uniform vec3 uColor;
      uniform float uSpacing;
      uniform vec2 uCenter;
      uniform float uReach;
      uniform float uOpacity;
      varying vec2 vWorld;
      void main() {
        vec2 g = abs(fract(vWorld / uSpacing - 0.5) - 0.5) / fwidth(vWorld / uSpacing);
        float line = 1.0 - min(min(g.x, g.y), 1.0);
        float fade = 1.0 - smoothstep(0.35, 1.0, length(vWorld - uCenter) / uReach);
        gl_FragColor = vec4(uColor, line * fade * 0.7 * uOpacity);
        #include <colorspace_fragment>
      }`,
  });
}

/** Shades a fat line like a tube: brighter along its middle, darker at its sides. */
export function tube(m: LineMaterial): LineMaterial {
  m.onBeforeCompile = (shader) => {
    shader.fragmentShader = shader.fragmentShader.replace(
      "gl_FragColor = vec4( diffuseColor.rgb, alpha );",
      [
        "float side = abs( vUv.x );",
        "gl_FragColor = vec4( diffuseColor.rgb * ( 0.8 + 0.45 * ( 1.0 - side * side ) ), alpha );",
      ].join("\n"),
    );
  };
  return m;
}
