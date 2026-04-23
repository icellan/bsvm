import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const here = path.dirname(fileURLToPath(import.meta.url));

function gitShortHash(): string {
  try {
    return execFileSync("git", ["rev-parse", "--short", "HEAD"], {
      cwd: here,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
  } catch {
    return "dev";
  }
}

// Vite outputs into pkg/webui/dist so the Go embed picks up the
// freshly built bundle on the next `go build`. The dev server
// proxies /rpc, /ws, /metrics, and /admin/rpc to the node so the
// explorer can run hot-reloading against a live devnet.
export default defineConfig({
  plugins: [react()],
  define: {
    __BUILD_HASH__: JSON.stringify(gitShortHash()),
  },
  resolve: {
    alias: {
      "@": path.resolve(here, "src"),
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
    outDir: path.resolve(here, "../pkg/webui/dist"),
    emptyOutDir: true,
    sourcemap: true,
  },
});
