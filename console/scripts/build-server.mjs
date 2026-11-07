import { copyFile, cp, mkdir, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { build } from "esbuild";

const serverRequire = createRequire(new URL("../server/package.json", import.meta.url));

await build({
  entryPoints: ["server/src/index.ts"],
  outfile: "dist/server/index.js",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  // node-pty resolves its native addon relative to its package at runtime, so
  // it cannot be folded into the single JS file like ordinary dependencies.
  external: ["node-pty"],
  // Fastify's CommonJS plugins contain runtime require() calls. Supplying an
  // ESM-scoped require keeps the single-file bundle compatible with them.
  banner: {
    js: 'import { createRequire as __aisocCreateRequire } from "node:module"; const require = __aisocCreateRequire(import.meta.url);',
  },
  logLevel: "warning",
});

await copyFile("server/src/intel/geo-table.txt", "dist/server/geo-table.txt");

const nodePtyRoot = dirname(serverRequire.resolve("node-pty/package.json"));
const nodePtyTarget = "dist/server/node_modules/node-pty";
await rm(nodePtyTarget, { recursive: true, force: true });
await mkdir(nodePtyTarget, { recursive: true });
await Promise.all([
  copyFile(join(nodePtyRoot, "package.json"), join(nodePtyTarget, "package.json")),
  cp(join(nodePtyRoot, "lib"), join(nodePtyTarget, "lib"), { recursive: true }),
  process.platform === "linux"
    ? cp(join(nodePtyRoot, "build", "Release"), join(nodePtyTarget, "build", "Release"), {
        recursive: true,
      })
    : cp(
        join(nodePtyRoot, "prebuilds", `${process.platform}-${process.arch}`),
        join(nodePtyTarget, "prebuilds", `${process.platform}-${process.arch}`),
        { recursive: true },
      ),
]);
