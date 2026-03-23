package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/Monet/seki/internal/config"
)

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg    *config.Config
	mux    *http.ServeMux
	server *http.Server
}

// New creates a new Server with the given configuration.
func New(cfg *config.Config) *Server {
	mux := http.NewServeMux()
	s := &Server{
		cfg: cfg,
		mux: mux,
		server: &http.Server{
			Addr:              cfg.Server.Address,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
	s.registerRoutes()
	return s
}

// registerRoutes sets up all HTTP routes.
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
}

// handleHealthz responds with a simple health check.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServe()
}

// Addr returns the server's listener address. Useful when using port :0.
func (s *Server) Addr() net.Addr {
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
