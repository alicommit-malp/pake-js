import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "spake2plus/index": "src/spake2plus/index.ts",
    "cpace/index": "src/cpace/index.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  minify: false,
  treeshake: true,
  target: "es2022",
  platform: "neutral",
  splitting: false,
  outDir: "dist",
});
