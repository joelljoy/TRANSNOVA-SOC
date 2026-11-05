import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Development only: the console backend (uvicorn console.serve:app --port 8501) serves the API and,
// in production, these built files. The browser never talks to the collector directly.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, strictPort: true, proxy: { "/api": { target: "http://127.0.0.1:8501", changeOrigin: false } } },
  // assetsInlineLimit 0: fonts ship as files, so the console CSP can keep font-src 'self' with no data: URIs.
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 700, assetsInlineLimit: 0 },
});
