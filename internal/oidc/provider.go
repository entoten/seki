package oidc

import (
	"net/http"

	"github.com/Monet/seki/internal/crypto"
	"github.com/Monet/seki/internal/storage"
)

// Provider serves OIDC discovery and JWKS endpoints.
type Provider struct {
	issuer string
	signer crypto.Signer
	store  storage.Storage
}

// NewProvider creates a new OIDC Provider.
func NewProvider(issuer string, signer crypto.Signer, store storage.Storage) *Provider {
	return &Provider{
		issuer: issuer,
		signer: signer,
		store:  store,
	}
}

// RegisterRoutes registers the OIDC discovery and JWKS routes on the given mux.
func (p *Provider) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", p.handleJWKS)
}
