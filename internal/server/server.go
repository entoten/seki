package server

import (
	"net/http"

	"github.com/Monet/seki/internal/config"
)

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg *config.Config
	mux *http.ServeMux
}

// New creates a new Server with the given configuration.
func New(cfg *config.Config) *Server {
	return &Server{
		cfg: cfg,
		mux: http.NewServeMux(),
	}
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.cfg.Server.Address, s.mux)
}
