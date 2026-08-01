package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
)

//go:embed all:web
var webFS embed.FS

type app struct {
	configDir string
	statePath string
	proxy     *attestationProxyClient
	mux       *http.ServeMux
}

func newApp(configDir, statePath string) (*app, error) {
	a := &app{
		configDir: configDir,
		statePath: statePath,
		proxy:     newAttestationProxyClient(),
	}
	a.mux = a.routes()
	return a, nil
}

func (a *app) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /livez", a.handleLivez)
	mux.HandleFunc("GET /api/info", a.handleAPIInfo)
	mux.HandleFunc("POST /api/verify", a.handleAPIVerify)
	mux.HandleFunc("GET /api/proxy/info", a.handleProxyInfo)

	// Static dashboard assets.
	assets, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /app.css", http.FileServerFS(assets))
	mux.Handle("GET /app.js", http.FileServerFS(assets))
	mux.Handle("GET /verify.js", http.FileServerFS(assets))
	mux.Handle("GET /favicon.svg", http.FileServerFS(assets))
	mux.HandleFunc("GET /", a.handleIndex)

	return mux
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'none'; frame-ancestors 'none'; img-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'")
	w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	a.mux.ServeHTTP(w, r)
}

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "index unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (a *app) handleLivez(w http.ResponseWriter, r *http.Request) {
	facts := gatherRuntimeFacts(a.configDir, a.statePath)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"service":      "prove-it",
		"version":      proveItVersion,
		"config_ready": facts.ConfigReady,
	})
}

// writeJSON never caches and never fails to send a body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
