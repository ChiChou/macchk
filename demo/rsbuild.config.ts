import { defineConfig } from "@rsbuild/core";

export default defineConfig({
  html: {
    template: "./index.html",
  },
  output: {
    assetPrefix: "./",
  },
  source: {
    entry: {
      index: "./src/main.ts",
    },
    tsconfigPath: "./tsconfig.json",
  },
});
