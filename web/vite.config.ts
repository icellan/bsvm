import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Vite outputs into pkg/webui/dist so the Go embed picks up the
// freshly built bundle on the next `go build`. The dev server
// proxies /rpc, /ws, /metrics, and /admin/rpc to the node so the
// explorer can run hot-reloading against a live devnet.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // JSON-RPC endpoints — POST passes through to the node.
      "/rpc": "http://localhost:8545",
      "/admin/rpc": "http://localhost:8545",
      "/.well-known/auth": "http://localhost:8545",
      "/metrics": "http://localhost:8545",
      // WebSocket — eth_subscribe / adminLogs.
      "/ws": {
        target: "ws://localhost:8546",
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: path.resolve(__dirname, "../pkg/webui/dist"),
    emptyOutDir: true,
    sourcemap: true,
  },
});
