package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/Monet/seki/internal/admin"
	"github.com/Monet/seki/internal/audit"
	"github.com/Monet/seki/internal/authn/passkey"
	"github.com/Monet/seki/internal/authn/password"
	"github.com/Monet/seki/internal/authn/social"
	"github.com/Monet/seki/internal/authn/totp"
	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/crypto"
	"github.com/Monet/seki/internal/oidc"
	"github.com/Monet/seki/internal/session"
	"github.com/Monet/seki/internal/storage"
	"github.com/Monet/seki/internal/webhook"
)

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg      *config.Config
	store    storage.Storage
	signer   crypto.Signer
	sessions *session.Manager
	audit    *audit.Logger
	webhooks *webhook.Emitter
	mux      *http.ServeMux
	server   *http.Server
}

// New creates a new Server with the given configuration.
func New(cfg *config.Config, store storage.Storage, signer crypto.Signer) *Server {
	mux := http.NewServeMux()

	// Session manager.
	sessMgr := session.NewManager(store, session.Config{})

	// Audit logger.
	auditLogger := audit.NewLogger(store, cfg.Audit)

	// Webhook emitter.
	webhookEmitter := webhook.NewEmitter(cfg.Webhooks)

	s := &Server{
		cfg:      cfg,
		store:    store,
		signer:   signer,
		sessions: sessMgr,
		audit:    auditLogger,
		webhooks: webhookEmitter,
		mux:      mux,
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
	// Health check.
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// OIDC provider with session manager and authentication config.
	provider := oidc.NewProvider(
		s.cfg.Server.Issuer,
		s.signer,
		s.store,
		oidc.WithSessionManager(s.sessions),
		oidc.WithAuthenticationConfig(s.cfg.Authentication),
	)
	provider.RegisterRoutes(s.mux)

	// Admin API routes.
	if s.store != nil {
		adminHandler := admin.NewHandler(s.store, s.cfg.Admin.APIKeys...)
		adminHandler.RegisterRoutes(s.mux)
	}

	// Authentication method routes.
	s.registerAuthnRoutes()
}

// registerAuthnRoutes registers authentication method handlers based on config.
func (s *Server) registerAuthnRoutes() {
	authnCfg := s.cfg.Authentication

	// Passkey (WebAuthn).
	if authnCfg.Passkey.Enabled {
		svc, err := passkey.NewService(authnCfg.Passkey, s.store)
		if err == nil {
			passkeyHandler := passkey.NewHandler(svc, s.store, s.sessions)
			passkeyHandler.RegisterRoutes(s.mux)
		}
	}

	// TOTP.
	if authnCfg.TOTP.Enabled {
		svc := totp.NewService(authnCfg.TOTP, s.store)
		totpHandler := totp.NewHandler(svc, s.store)
		totpHandler.RegisterRoutes(s.mux)
	}

	// Password.
	if authnCfg.Password.Enabled {
		svc := password.NewService(s.store)
		pwHandler := password.NewHandler(svc, s.store)
		pwHandler.RegisterRoutes(s.mux)
	}

	// Social login.
	if len(authnCfg.Social) > 0 {
		svc := social.NewService(authnCfg.Social, s.store)
		socialHandler := social.NewHandler(svc, s.cfg.Server.Issuer)
		socialHandler.RegisterRoutes(s.mux)
	}
}

// handleHealthz responds with a simple health check.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// Optionally check storage connectivity.
	status := "ok"
	httpStatus := http.StatusOK
	if s.store != nil {
		if err := s.store.Ping(r.Context()); err != nil {
			status = "degraded"
			httpStatus = http.StatusServiceUnavailable
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(map[string]string{"status": status})
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

// AuditLogger returns the server's audit logger for use by callers.
func (s *Server) AuditLogger() *audit.Logger {
	return s.audit
}

// WebhookEmitter returns the server's webhook emitter for use by callers.
func (s *Server) WebhookEmitter() *webhook.Emitter {
	return s.webhooks
}
