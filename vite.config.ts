import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  build: {
    outDir: "agentic_observatory/static/dist",
    emptyOutDir: true,
    rollupOptions: {
      input: "frontend/src/main.ts",
      output: {
        entryFileNames: "main.js",
        chunkFileNames: "[name].js",
        assetFileNames: "[name][extname]",
      },
    },
  },
});
