package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Monet/seki/internal/admin"
	"github.com/Monet/seki/internal/audit"
	"github.com/Monet/seki/internal/authn/passkey"
	"github.com/Monet/seki/internal/authn/password"
	"github.com/Monet/seki/internal/authn/social"
	"github.com/Monet/seki/internal/authn/totp"
	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/crypto"
	"github.com/Monet/seki/internal/metrics"
	"github.com/Monet/seki/internal/middleware"
	"github.com/Monet/seki/internal/oidc"
	"github.com/Monet/seki/internal/ratelimit"
	"github.com/Monet/seki/internal/scim"
	"github.com/Monet/seki/internal/session"
	"github.com/Monet/seki/internal/storage"
	"github.com/Monet/seki/internal/webhook"
	adminui "github.com/Monet/seki/web/admin"
)

// Server wraps the HTTP server and its dependencies.
type Server struct {
	cfg      *config.Config
	store    storage.Storage
	signer   crypto.Signer
	sessions *session.Manager
	audit    *audit.Logger
	webhooks *webhook.Emitter
	limiter  *ratelimit.Limiter
	mux      *http.ServeMux
	server   *http.Server
}

// New creates a new Server with the given configuration.
func New(cfg *config.Config, store storage.Storage, signer crypto.Signer) *Server {
	mux := http.NewServeMux()

	// Session manager.
	sessMgr := session.NewManager(store, session.Config{
		MaxConcurrentSessions: cfg.Session.MaxConcurrentSessions,
	})

	// Audit logger.
	auditLogger := audit.NewLogger(store, cfg.Audit)

	// Webhook emitter.
	webhookEmitter := webhook.NewEmitter(cfg.Webhooks)

	// Register Prometheus metrics.
	metrics.Register()

	// Rate limiter (optional).
	var limiter *ratelimit.Limiter
	if cfg.RateLimit.Enabled {
		limiter = ratelimit.NewLimiter(cfg.RateLimit)
	}

	// Build middleware chain (outermost first):
	// RequestID -> Recovery -> SecurityHeaders -> CORS -> RateLimit -> Metrics -> Router
	var handler http.Handler = mux
	handler = metrics.Middleware(handler)
	if limiter != nil {
		handler = ratelimit.HTTPMiddleware(limiter)(handler)
	}
	handler = middleware.CORS(cfg.CORS)(handler)
	handler = middleware.SecurityHeaders()(handler)
	handler = middleware.Recovery()(handler)
	handler = middleware.RequestID()(handler)

	s := &Server{
		cfg:      cfg,
		store:    store,
		signer:   signer,
		sessions: sessMgr,
		audit:    auditLogger,
		webhooks: webhookEmitter,
		limiter:  limiter,
		mux:      mux,
		server: &http.Server{
			Addr:              cfg.Server.Address,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
	s.registerRoutes()
	return s
}

// registerRoutes sets up all HTTP routes.
func (s *Server) registerRoutes() {
	// Health check endpoints.
	s.mux.HandleFunc("GET /healthz", s.handleHealthzReady)
	s.mux.HandleFunc("GET /healthz/ready", s.handleHealthzReady)
	s.mux.HandleFunc("GET /healthz/live", s.handleHealthzLive)

	// Prometheus metrics.
	s.mux.Handle("GET /metrics", promhttp.Handler())

	// OIDC provider with session manager, authentication config, and rate limiter.
	providerOpts := []oidc.ProviderOption{
		oidc.WithSessionManager(s.sessions),
		oidc.WithAuthenticationConfig(s.cfg.Authentication),
	}
	if s.limiter != nil {
		providerOpts = append(providerOpts, oidc.WithRateLimiter(s.limiter))
	}
	provider := oidc.NewProvider(
		s.cfg.Server.Issuer,
		s.signer,
		s.store,
		providerOpts...,
	)
	provider.RegisterRoutes(s.mux)

	// Admin API routes.
	if s.store != nil {
		adminHandler := admin.NewHandler(s.store, s.cfg.Admin.APIKeys...)
		adminHandler.RegisterRoutes(s.mux)
	}

	// SCIM 2.0 provisioning routes.
	if s.store != nil {
		scimHandler := scim.NewHandler(s.store, s.cfg.Server.Issuer, s.cfg.Admin.APIKeys...)
		scimHandler.RegisterRoutes(s.mux)
	}

	// Admin UI (embedded SPA).
	adminFS, _ := fs.Sub(adminui.FS, ".")
	s.mux.Handle("GET /admin", http.RedirectHandler("/admin/", http.StatusMovedPermanently))
	s.mux.Handle("GET /admin/", http.StripPrefix("/admin/", http.FileServer(http.FS(adminFS))))

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

// handleHealthzLive responds with 200 if the process is running (liveness probe).
func (s *Server) handleHealthzLive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
}

// handleHealthzReady checks DB connectivity (readiness probe).
func (s *Server) handleHealthzReady(w http.ResponseWriter, r *http.Request) {
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

// ServeHTTP implements http.Handler, delegating to the inner server handler.
// This is useful for testing without starting a network listener.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.server.Handler.ServeHTTP(w, r)
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
	if s.limiter != nil {
		s.limiter.Stop()
	}
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
