package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/validate"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// registrationRequest represents a dynamic client registration request (RFC 7591).
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// registrationResponse represents the response to a dynamic client registration request.
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
}

// handleRegister implements the dynamic client registration endpoint (RFC 7591/7592).
// POST /register     - register a new client
// GET /register/{id} - read client registration (requires registration_access_token)
// PUT /register/{id} - update client registration (RFC 7592)
// DELETE /register/{id} - delete client registration (RFC 7592)
func (p *Provider) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Extract the path to determine if this is a management request.
	path := r.URL.Path
	prefix := "/register/"

	switch {
	case r.Method == http.MethodPost && path == "/register":
		p.handleRegisterCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, prefix):
		clientID := strings.TrimPrefix(path, prefix)
		p.handleRegisterRead(w, r, clientID)
	case r.Method == http.MethodPut && strings.HasPrefix(path, prefix):
		clientID := strings.TrimPrefix(path, prefix)
		p.handleRegisterUpdate(w, r, clientID)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, prefix):
		clientID := strings.TrimPrefix(path, prefix)
		p.handleRegisterDelete(w, r, clientID)
	default:
		tokenError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
	}
}

// handleRegisterCreate creates a new client dynamically.
func (p *Provider) handleRegisterCreate(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid request body")
		return
	}

	// Validate redirect_uris.
	if len(req.RedirectURIs) == 0 {
		tokenError(w, http.StatusBadRequest, "invalid_redirect_uri", "at least one redirect_uri is required")
		return
	}
	if err := validate.RedirectURIs(req.RedirectURIs); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
		return
	}

	// Default grant_types and response_types.
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	// Validate grant_types.
	allowedGrants := map[string]bool{
		"authorization_code": true,
		"client_credentials": true,
		"refresh_token":      true,
	}
	for _, gt := range grantTypes {
		if !allowedGrants[gt] {
			tokenError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant_type: "+gt)
			return
		}
	}

	// Validate response_types.
	for _, rt := range responseTypes {
		if rt != "code" {
			tokenError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response_type: "+rt)
			return
		}
	}

	// Default auth method.
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	allowedMethods := map[string]bool{
		"client_secret_basic": true,
		"client_secret_post":  true,
		"private_key_jwt":     true,
		"none":                true,
	}
	if !allowedMethods[authMethod] {
		tokenError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method: "+authMethod)
		return
	}

	// Generate client_id (UUID), client_secret, and registration_access_token.
	clientID := uuid.New().String()
	clientSecret, err := generateRandomSecret(32)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate client secret")
		return
	}
	rat, err := generateRandomSecret(32)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate registration access token")
		return
	}

	// Hash the client secret using bcrypt.
	secretHashBytes, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to hash client secret")
		return
	}

	// Hash the registration access token (SHA-256).
	ratHash := hashRAT(rat)

	clientName := req.ClientName
	if clientName == "" {
		clientName = "Dynamic Client " + clientID[:8]
	}

	now := time.Now().UTC()

	// Store the RAT hash in the client's metadata.
	metaObj := map[string]string{
		"registration_access_token_hash": ratHash,
	}
	metaBytes, _ := json.Marshal(metaObj)

	client := &storage.Client{
		ID:                      clientID,
		Name:                    clientName,
		SecretHash:              string(secretHashBytes),
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
		Scopes:                  []string{"openid", "profile", "email"},
		PKCERequired:            false,
		TokenEndpointAuthMethod: authMethod,
		Metadata:                json.RawMessage(metaBytes),
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	if err := p.store.CreateClient(r.Context(), client); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to create client")
		return
	}

	issuer := strings.TrimRight(p.issuer, "/")

	resp := registrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        now.Unix(),
		ClientSecretExpiresAt:   0, // does not expire
		RedirectURIs:            req.RedirectURIs,
		ClientName:              clientName,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
		RegistrationAccessToken: rat,
		RegistrationClientURI:   issuer + "/register/" + clientID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleRegisterRead returns client registration information.
func (p *Provider) handleRegisterRead(w http.ResponseWriter, r *http.Request, clientID string) {
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			tokenError(w, http.StatusNotFound, "invalid_client", "client not found")
			return
		}
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to look up client")
		return
	}

	// Verify registration_access_token.
	if !p.verifyRAT(r, client) {
		tokenError(w, http.StatusUnauthorized, "invalid_token", "invalid or missing registration access token")
		return
	}

	issuer := strings.TrimRight(p.issuer, "/")
	resp := registrationResponse{
		ClientID:                client.ID,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   0,
		RedirectURIs:            client.RedirectURIs,
		ClientName:              client.Name,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		RegistrationClientURI:   issuer + "/register/" + client.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleRegisterUpdate updates client registration (RFC 7592).
func (p *Provider) handleRegisterUpdate(w http.ResponseWriter, r *http.Request, clientID string) {
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			tokenError(w, http.StatusNotFound, "invalid_client", "client not found")
			return
		}
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to look up client")
		return
	}

	// Verify registration_access_token.
	if !p.verifyRAT(r, client) {
		tokenError(w, http.StatusUnauthorized, "invalid_token", "invalid or missing registration access token")
		return
	}

	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid request body")
		return
	}

	// Validate redirect_uris if provided.
	if len(req.RedirectURIs) > 0 {
		if err := validate.RedirectURIs(req.RedirectURIs); err != nil {
			tokenError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
		client.RedirectURIs = req.RedirectURIs
	}

	if req.ClientName != "" {
		client.Name = req.ClientName
	}
	if len(req.GrantTypes) > 0 {
		client.GrantTypes = req.GrantTypes
	}
	if req.TokenEndpointAuthMethod != "" {
		client.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}

	client.UpdatedAt = time.Now().UTC()

	if err := p.store.UpdateClient(r.Context(), client); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to update client")
		return
	}

	issuer := strings.TrimRight(p.issuer, "/")
	resp := registrationResponse{
		ClientID:                client.ID,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   0,
		RedirectURIs:            client.RedirectURIs,
		ClientName:              client.Name,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		RegistrationClientURI:   issuer + "/register/" + client.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleRegisterDelete deletes a dynamically registered client.
func (p *Provider) handleRegisterDelete(w http.ResponseWriter, r *http.Request, clientID string) {
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			tokenError(w, http.StatusNotFound, "invalid_client", "client not found")
			return
		}
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to look up client")
		return
	}

	// Verify registration_access_token.
	if !p.verifyRAT(r, client) {
		tokenError(w, http.StatusUnauthorized, "invalid_token", "invalid or missing registration access token")
		return
	}

	if err := p.store.DeleteClient(r.Context(), clientID); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to delete client")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// verifyRAT verifies the registration access token from the Authorization header
// against the hash stored in the client's metadata.
func (p *Provider) verifyRAT(r *http.Request, client *storage.Client) bool {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Extract the stored hash from metadata.
	var meta map[string]string
	if err := json.Unmarshal(client.Metadata, &meta); err != nil {
		return false
	}

	storedHash, ok := meta["registration_access_token_hash"]
	if !ok {
		return false
	}

	return hashRAT(token) == storedHash
}

// hashRAT returns the hex-encoded SHA-256 hash of a registration access token.
func hashRAT(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// generateRandomSecret generates a cryptographically random secret of the given byte length.
func generateRandomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
