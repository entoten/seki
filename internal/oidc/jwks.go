package oidc

import (
	"encoding/json"
	"net/http"
)

// handleJWKS serves the JSON Web Key Set containing the provider's public signing key(s).
func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := map[string]interface{}{
		"keys": []interface{}{
			p.signer.PublicKeyJWK(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(jwks)
}
