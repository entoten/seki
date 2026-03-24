package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
)

// handleDiscovery serves the OpenID Connect Discovery 1.0 metadata document.
func (p *Provider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(p.issuer, "/")

	metadata := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"},
		"device_authorization_endpoint":         issuer + "/device/code",
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{p.signer.Algorithm()},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"introspection_endpoint":                issuer + "/introspect",
		"revocation_endpoint":                   issuer + "/revoke",
		"acr_values_supported":                          []string{ACRBasic, ACRMFA},
		"dpop_signing_alg_values_supported":              []string{"ES256", "EdDSA"},
		"pushed_authorization_request_endpoint":          issuer + "/par",
		"require_pushed_authorization_requests":          false,
		"authorization_response_iss_parameter_supported": true,
		"backchannel_logout_supported":                   true,
		"backchannel_logout_session_supported":           true,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(metadata)
}

// handleOAuthASMetadata serves the OAuth 2.0 Authorization Server Metadata (RFC 8414).
// It returns the same metadata as OIDC Discovery minus OIDC-specific fields.
func (p *Provider) handleOAuthASMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(p.issuer, "/")

	metadata := map[string]interface{}{
		"issuer":                                          issuer,
		"authorization_endpoint":                          issuer + "/authorize",
		"token_endpoint":                                  issuer + "/token",
		"jwks_uri":                                        issuer + "/.well-known/jwks.json",
		"scopes_supported":                                []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":                        []string{"code"},
		"device_authorization_endpoint":                   issuer + "/device/code",
		"grant_types_supported":                           []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"token_endpoint_auth_methods_supported":           []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"code_challenge_methods_supported":                []string{"S256"},
		"introspection_endpoint":                          issuer + "/introspect",
		"revocation_endpoint":                             issuer + "/revoke",
		"dpop_signing_alg_values_supported":               []string{"ES256", "EdDSA"},
		"pushed_authorization_request_endpoint":           issuer + "/par",
		"require_pushed_authorization_requests":           false,
		"authorization_response_iss_parameter_supported":  true,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(metadata)
}
