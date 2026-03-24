package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/telemetry"
	"github.com/entoten/seki/internal/validate"
)

const parRequestTTL = 60 * time.Second

// parRequest stores the authorization parameters submitted via PAR.
type parRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ACRValues           string
	ExpiresAt           time.Time
}

// parStore is an in-memory store for pushed authorization requests with TTL.
type parStore struct {
	mu       sync.Mutex
	requests map[string]*parRequest
	lastGC   time.Time
}

func newPARStore() *parStore {
	return &parStore{
		requests: make(map[string]*parRequest),
		lastGC:   time.Now(),
	}
}

// store saves a PAR request and returns its request_uri.
func (s *parStore) store(req *parRequest) (string, error) {
	uri, err := generateRequestURI()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Garbage-collect expired entries periodically.
	now := time.Now()
	if now.Sub(s.lastGC) > 30*time.Second {
		for k, v := range s.requests {
			if now.After(v.ExpiresAt) {
				delete(s.requests, k)
			}
		}
		s.lastGC = now
	}

	s.requests[uri] = req
	return uri, nil
}

// get retrieves and deletes a PAR request (single-use).
func (s *parStore) get(uri string) (*parRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[uri]
	if !ok {
		return nil, errors.New("request_uri not found")
	}

	// Delete immediately (single-use).
	delete(s.requests, uri)

	if time.Now().After(req.ExpiresAt) {
		return nil, errors.New("request_uri has expired")
	}

	return req, nil
}

// generateRequestURI creates a unique request_uri per RFC 9126.
func generateRequestURI() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating request uri: %w", err)
	}
	return "urn:ietf:params:oauth:request_uri:" + base64.RawURLEncoding.EncodeToString(b), nil
}

// handlePAR implements the Pushed Authorization Request endpoint (RFC 9126).
// POST /par
func (p *Provider) handlePAR(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.par")
	defer span.End()
	r = r.WithContext(ctx)

	if r.Method != http.MethodPost {
		tokenError(w, http.StatusMethodNotAllowed, "invalid_request", "method must be POST")
		return
	}

	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	// Authenticate the client.
	client, err := p.authenticateClient(r)
	if err != nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	// Extract authorization parameters.
	redirectURI := r.PostFormValue("redirect_uri")
	responseType := r.PostFormValue("response_type")
	scope := r.PostFormValue("scope")
	state := r.PostFormValue("state")
	nonce := r.PostFormValue("nonce")
	codeChallenge := r.PostFormValue("code_challenge")
	codeChallengeMethod := r.PostFormValue("code_challenge_method")
	acrValues := r.PostFormValue("acr_values")

	// Validate redirect_uri.
	if err := validate.RedirectURI(redirectURI); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !isValidRedirectURI(client, redirectURI) {
		tokenError(w, http.StatusBadRequest, "invalid_request", "redirect_uri does not match any registered URI for this client")
		return
	}

	// Validate response_type.
	if responseType == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "missing response_type parameter")
		return
	}
	if responseType != "code" {
		tokenError(w, http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}

	// Validate scope.
	scopes := parseScopes(scope)
	if !containsScope(scopes, "openid") {
		tokenError(w, http.StatusBadRequest, "invalid_scope", "scope must include openid")
		return
	}

	// Validate PKCE.
	if client.PKCERequired {
		if codeChallenge == "" {
			tokenError(w, http.StatusBadRequest, "invalid_request", "code_challenge is required")
			return
		}
		if codeChallengeMethod == "" {
			tokenError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method is required")
			return
		}
	}
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "only code_challenge_method=S256 is supported")
		return
	}

	// Store the request.
	parReq := &parRequest{
		ClientID:            client.ID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ACRValues:           acrValues,
		ExpiresAt:           time.Now().Add(parRequestTTL),
	}

	requestURI, err := p.parStore.store(parReq)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to store pushed authorization request")
		return
	}

	// Return the response.
	resp := map[string]interface{}{
		"request_uri": requestURI,
		"expires_in":  int(parRequestTTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// resolveAuthorizeParamsFromPAR checks if the authorize request has a request_uri
// parameter and resolves it from the PAR store. If found, it overrides query params.
// Returns the client and parameters to use, or writes an error and returns nil.
func (p *Provider) resolveAuthorizeParamsFromPAR(w http.ResponseWriter, r *http.Request) (*storage.Client, *parRequest, bool) {
	q := r.URL.Query()
	requestURI := q.Get("request_uri")
	if requestURI == "" {
		return nil, nil, false
	}

	parReq, err := p.parStore.get(requestURI)
	if err != nil {
		renderError(w, http.StatusBadRequest, "invalid_request", "invalid or expired request_uri: "+err.Error())
		return nil, nil, true
	}

	// Look up the client to return it.
	client, err := p.store.GetClient(r.Context(), parReq.ClientID)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "server_error", "failed to look up client")
		return nil, nil, true
	}

	return client, parReq, true
}
