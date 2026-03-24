package oidc

import (
	"encoding/json"
	"net/http"

	"github.com/entoten/seki/internal/crypto"
)

// handleJWKS serves the JSON Web Key Set containing the provider's public signing key(s).
func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	var keys []interface{}

	// If the signer is a KeySet, return all public keys (current + rotated).
	if ks, ok := p.signer.(*crypto.KeySet); ok {
		for _, k := range ks.AllPublicKeys() {
			keys = append(keys, k)
		}
	} else {
		keys = []interface{}{p.signer.PublicKeyJWK()}
	}

	jwks := map[string]interface{}{
		"keys": keys,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=900")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(jwks)
}
