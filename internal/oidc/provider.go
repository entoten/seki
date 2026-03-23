package oidc

import (
	"net/http"

	"github.com/Monet/seki/internal/crypto"
	"github.com/Monet/seki/internal/session"
	"github.com/Monet/seki/internal/storage"
)

// Provider serves OIDC discovery and JWKS endpoints.
type Provider struct {
	issuer   string
	signer   crypto.Signer
	store    storage.Storage
	sessions *session.Manager
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

// RegisterRoutes registers the OIDC discovery and JWKS routes on the given mux.
func (p *Provider) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", p.handleJWKS)
	mux.HandleFunc("GET /authorize", p.handleAuthorize)
	mux.HandleFunc("POST /token", p.handleToken)
}
