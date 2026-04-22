import { defineConfig } from "tsup";

// Separate entry per middleware so Express users don't download Fastify
// code, and vice versa. Each becomes its own chunk in dist/.
export default defineConfig({
  entry: {
    "index": "src/index.ts",
    "middleware/express": "src/middleware/express.ts",
    "middleware/fastify": "src/middleware/fastify.ts",
    // hono, nest entries land in a follow-up -- see tests/
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  treeshake: true,
  target: "node18",
  outDir: "dist",
  // Do not bundle peer deps into the package.
  external: ["pg", "express", "fastify", "hono", "@nestjs/common"],
});
