// Package webui embeds the BSVM explorer / admin SPA into the Go
// binary so `GET /` on the RPC server can serve HTML without any
// out-of-band static file hosting.
//
// Spec 15 describes a React SPA built by Vite; until that lands the
// `dist/` directory contains a placeholder page that shows live node
// status via JSON-RPC calls. Swapping in the real SPA is a matter of
// replacing `dist/` with the Vite build output — nothing else in the
// server needs to change.
//
// Build tag `noui` excludes the embed so operators who want a minimal
// node binary (no HTTP surface beyond JSON-RPC) can drop the ~30 KB
// assets.

//go:build !noui

package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// dist holds the compiled SPA. When `pkg/webui/dist/` is replaced by a
// real Vite build, the embed picks it up automatically on the next
// `go build`.
//
//go:embed all:dist
var dist embed.FS

// Handler returns an http.Handler that serves the embedded SPA.
//
// Routing behaviour:
//
//   - `GET /` returns `dist/index.html`.
//   - `GET /assets/*` serves assets verbatim from the embed.
//   - Any other `GET` path that doesn't match an asset also returns
//     index.html (history-API fallback — the SPA owns client-side
//     routing for `/block/:n`, `/tx/:hash`, etc.).
//
// Non-GET methods fall through to the provided `rpc` handler so the
// same URL namespace hosts POST JSON-RPC and GET SPA without needing
// two ports.
func Handler(rpc http.Handler) http.Handler {
	assets, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("webui: unable to open embedded dist filesystem: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(assets))

	index, indexErr := fs.ReadFile(assets, "index.html")
	if indexErr != nil {
		panic("webui: embedded dist missing index.html: " + indexErr.Error())
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Non-GET → delegate to JSON-RPC. Covers POST requests and any
		// other verbs the SPA never needs.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			rpc.ServeHTTP(w, r)
			return
		}

		// Normalise the request path for matching.
		reqPath := strings.TrimPrefix(r.URL.Path, "/")
		if reqPath == "" {
			serveIndex(w, index)
			return
		}

		// `/metrics` is owned by the Prometheus handler, so never
		// shadow it here. We also skip anything that looks like a JSON
		// content type, to let clients that POST without a body for
		// diagnostic reasons still reach the RPC dispatcher.
		if reqPath == "metrics" {
			rpc.ServeHTTP(w, r)
			return
		}

		// Explicit asset lookup. Anything under /assets/* must exist
		// on disk or be a 404 — don't fall back to index.html for
		// missing assets, since that would mask typos in the SPA.
		if strings.HasPrefix(reqPath, "assets/") {
			if _, err := fs.Stat(assets, reqPath); err != nil {
				http.NotFound(w, r)
				return
			}
			fileServer.ServeHTTP(w, r)
			return
		}

		// Top-level static files (favicon, manifest, etc.) — serve if
		// present, otherwise treat as a client-side route.
		if _, err := fs.Stat(assets, reqPath); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		// History-API fallback: any other GET is a SPA route.
		serveIndex(w, index)
	})
}

// serveIndex writes the embedded index.html with sensible defaults.
func serveIndex(w http.ResponseWriter, index []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// SPA HTML changes every build; don't cache aggressively.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(index)
}

// FSRoot returns the embedded `dist/` filesystem. Exposed so tests can
// assert on its contents without re-importing the embed directive.
func FSRoot() fs.FS {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	return root
}

// AssetPath joins a relative asset path onto the embed root. Used by
// tests that need to open a specific file without re-deriving the
// "dist/" prefix.
func AssetPath(p string) string {
	return path.Clean(path.Join("/", p))
}
