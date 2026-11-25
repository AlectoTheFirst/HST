/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";

const require = createRequire(import.meta.url);

const LICENSE_FILE = /^(licen[cs]e|copying|notice)(\.|$)/i;

/** The directory of the node_modules package that holds the module `id`, or null. */
function packageRoot(id: string): string | null {
  const path = id.replace(/\\/g, "/").replace(/^\0+/, "").split("?")[0];
  const marker = "/node_modules/";
  const at = path.lastIndexOf(marker);
  if (at < 0) return null;
  const parts = path.slice(at + marker.length).split("/");
  const name = parts[0].startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0];
  return path.slice(0, at + marker.length) + name;
}

/**
 * Writes `THIRD-PARTY-LICENSES.txt`: the name, the version, the licence and the
 * licence files of each node_modules package that the bundle includes.
 */
function thirdPartyLicenses(): Plugin {
  return {
    name: "third-party-licenses",
    apply: "build",
    generateBundle() {
      const roots = new Set<string>();
      for (const id of this.getModuleIds()) {
        const root = packageRoot(id);
        if (root && existsSync(resolve(root, "package.json"))) roots.add(root);
      }
      const sections = [...roots]
        .map((root) => {
          const manifest = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
            name: string;
            version: string;
            license?: string;
            repository?: string | { url?: string };
          };
          const repository =
            typeof manifest.repository === "string" ? manifest.repository : manifest.repository?.url;
          const texts = readdirSync(root)
            .filter((file) => LICENSE_FILE.test(file))
            .sort()
            .map((file) => readFileSync(resolve(root, file), "utf8").trim());
          const head = [
            `${manifest.name} ${manifest.version}`,
            `Licence: ${manifest.license ?? "not declared"}`,
            `Source: ${repository ?? "not declared"}`,
          ].join("\n");
          return { name: manifest.name, text: [head, ...texts].join("\n\n") };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
      const rule = `\n\n${"-".repeat(72)}\n\n`;
      this.emitFile({
        type: "asset",
        fileName: "THIRD-PARTY-LICENSES.txt",
        source: sections.map((section) => section.text).join(rule) + "\n",
      });
    },
  };
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), thirdPartyLicenses(), {
    name: "swagger-ui-assets",
    writeBundle(options) {
      const source = dirname(require.resolve("swagger-ui-dist/package.json"));
      const target = resolve(options.dir ?? "dist", "swagger-ui");
      mkdirSync(target, { recursive: true });
      for (const name of [
        "swagger-ui.css", "swagger-ui-bundle.js", "swagger-ui-bundle.js.LICENSE.txt", "LICENSE", "NOTICE",
      ]) {
        copyFileSync(resolve(source, name), resolve(target, name));
      }
    },
  }],
  build: {
    outDir: "dist",
  },
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // The Testing Library timeout in src/test/setup.ts is 5000 ms.
    testTimeout: process.env.CI ? 30_000 : 5_000,
  },
});
