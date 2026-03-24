package oidc

import (
	"net/http"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/crypto"
	"github.com/Monet/seki/internal/ratelimit"
	"github.com/Monet/seki/internal/session"
	"github.com/Monet/seki/internal/storage"
)

// Provider serves OIDC discovery and JWKS endpoints.
type Provider struct {
	issuer      string
	signer      crypto.Signer
	store       storage.Storage
	sessions    *session.Manager
	authnConfig config.AuthenticationConfig
	limiter     *ratelimit.Limiter
}

// NewProvider creates a new OIDC Provider.
func NewProvider(issuer string, signer crypto.Signer, store storage.Storage, opts ...ProviderOption) *Provider {
	p := &Provider{
		issuer: issuer,
		signer: signer,
		store:  store,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ProviderOption configures a Provider.
type ProviderOption func(*Provider)

// WithSessionManager sets the session manager on the provider.
func WithSessionManager(mgr *session.Manager) ProviderOption {
	return func(p *Provider) {
		p.sessions = mgr
	}
}

// WithAuthenticationConfig sets the authentication method configuration.
func WithAuthenticationConfig(cfg config.AuthenticationConfig) ProviderOption {
	return func(p *Provider) {
		p.authnConfig = cfg
	}
}

// WithRateLimiter sets the rate limiter on the provider for login brute-force protection.
func WithRateLimiter(l *ratelimit.Limiter) ProviderOption {
	return func(p *Provider) {
		p.limiter = l
	}
}

// RegisterRoutes registers the OIDC discovery and JWKS routes on the given mux.
func (p *Provider) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", p.handleJWKS)
	mux.HandleFunc("GET /authorize", p.handleAuthorize)
	mux.HandleFunc("POST /token", p.handleToken)
	mux.HandleFunc("GET /userinfo", p.handleUserInfo)

	// Login / logout routes.
	mux.HandleFunc("GET /login", p.handleLoginPage)
	mux.HandleFunc("POST /login", p.handleLoginSubmit)
	mux.HandleFunc("POST /logout", p.handleLogout)

	// MFA step-up routes.
	mux.HandleFunc("GET /mfa", p.handleMFAPage)
	mux.HandleFunc("POST /mfa", p.handleMFASubmit)

	// Device authorization grant (RFC 8628).
	p.RegisterDeviceRoutes(mux)
}
