// Package passkey implements WebAuthn/Passkey registration and authentication.
package passkey

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
)

// Service provides WebAuthn registration and authentication operations.
type Service struct {
	wan   *webauthn.WebAuthn
	store storage.Storage
}

// NewService creates a new passkey Service from the given config and storage.
func NewService(cfg config.PasskeyConfig, store storage.Storage) (*Service, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("passkey: not enabled")
	}
	if cfg.RPID == "" {
		return nil, fmt.Errorf("passkey: rp_id is required")
	}
	if cfg.RPName == "" {
		cfg.RPName = cfg.RPID
	}

	wanCfg := &webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPName,
		RPOrigins:     buildOrigins(cfg.RPID),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
	}

	wan, err := webauthn.New(wanCfg)
	if err != nil {
		return nil, fmt.Errorf("passkey: create webauthn: %w", err)
	}

	return &Service{
		wan:   wan,
		store: store,
	}, nil
}

// BeginRegistration starts the WebAuthn registration ceremony for a user.
// It returns the credential creation options and session data (as a JSON string)
// that must be stored temporarily and passed to FinishRegistration.
func (s *Service) BeginRegistration(ctx context.Context, user *storage.User) (*protocol.CredentialCreation, string, error) {
	creds, err := s.store.ListCredentialsByUser(ctx, user.ID, "passkey")
	if err != nil {
		return nil, "", fmt.Errorf("passkey: list credentials: %w", err)
	}

	adapter := NewUserAdapter(user, creds)

	// Exclude existing credentials to prevent re-registration.
	excludeList := make([]protocol.CredentialDescriptor, len(creds))
	for i, c := range creds {
		excludeList[i] = protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    c.CredentialID,
		}
	}

	creation, session, err := s.wan.BeginRegistration(adapter,
		webauthn.WithExclusions(excludeList),
	)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin registration: %w", err)
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: marshal session: %w", err)
	}

	return creation, string(sessionJSON), nil
}

// FinishRegistration completes the WebAuthn registration ceremony. It verifies
// the attestation response and stores the new credential in the database.
func (s *Service) FinishRegistration(ctx context.Context, user *storage.User, sessionData string, response *http.Request) error {
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return fmt.Errorf("passkey: unmarshal session: %w", err)
	}

	creds, err := s.store.ListCredentialsByUser(ctx, user.ID, "passkey")
	if err != nil {
		return fmt.Errorf("passkey: list credentials: %w", err)
	}

	adapter := NewUserAdapter(user, creds)

	credential, err := s.wan.FinishRegistration(adapter, session, response)
	if err != nil {
		return fmt.Errorf("passkey: finish registration: %w", err)
	}

	now := time.Now().UTC()
	storageCred := &storage.Credential{
		ID:              uuid.New().String(),
		UserID:          user.ID,
		Type:            "passkey",
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		DisplayName:     "Passkey",
		LastUsedAt:      &now,
		CreatedAt:       now,
	}

	if err := s.store.CreateCredential(ctx, storageCred); err != nil {
		return fmt.Errorf("passkey: store credential: %w", err)
	}

	return nil
}

// BeginLogin starts the WebAuthn login ceremony for a known user.
// It returns assertion options and session data (as JSON string).
func (s *Service) BeginLogin(ctx context.Context, user *storage.User) (*protocol.CredentialAssertion, string, error) {
	creds, err := s.store.ListCredentialsByUser(ctx, user.ID, "passkey")
	if err != nil {
		return nil, "", fmt.Errorf("passkey: list credentials: %w", err)
	}

	adapter := NewUserAdapter(user, creds)

	assertion, session, err := s.wan.BeginLogin(adapter)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin login: %w", err)
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: marshal session: %w", err)
	}

	return assertion, string(sessionJSON), nil
}

// FinishLogin completes the WebAuthn login ceremony. It verifies the assertion
// response, updates the sign count and last_used_at, and returns the matched credential.
func (s *Service) FinishLogin(ctx context.Context, user *storage.User, sessionData string, response *http.Request) (*storage.Credential, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return nil, fmt.Errorf("passkey: unmarshal session: %w", err)
	}

	creds, err := s.store.ListCredentialsByUser(ctx, user.ID, "passkey")
	if err != nil {
		return nil, fmt.Errorf("passkey: list credentials: %w", err)
	}

	adapter := NewUserAdapter(user, creds)

	credential, err := s.wan.FinishLogin(adapter, session, response)
	if err != nil {
		return nil, fmt.Errorf("passkey: finish login: %w", err)
	}

	// Find the matching storage credential and update sign count.
	storageCred, err := s.store.GetCredentialByCredentialID(ctx, credential.ID)
	if err != nil {
		return nil, fmt.Errorf("passkey: find credential: %w", err)
	}

	now := time.Now().UTC()
	if err := s.store.UpdateCredentialSignCount(ctx, storageCred.ID, credential.Authenticator.SignCount, now); err != nil {
		return nil, fmt.Errorf("passkey: update sign count: %w", err)
	}

	storageCred.SignCount = credential.Authenticator.SignCount
	storageCred.LastUsedAt = &now

	return storageCred, nil
}

// BeginDiscoverableLogin starts a WebAuthn discoverable login ceremony
// (passkey login without username / resident key).
func (s *Service) BeginDiscoverableLogin(_ context.Context) (*protocol.CredentialAssertion, string, error) {
	assertion, session, err := s.wan.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin discoverable login: %w", err)
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: marshal session: %w", err)
	}

	return assertion, string(sessionJSON), nil
}

// FinishDiscoverableLogin completes a discoverable login ceremony. It resolves
// the user from the credential's userHandle and returns the user and credential.
func (s *Service) FinishDiscoverableLogin(ctx context.Context, sessionData string, response *http.Request) (*storage.User, *storage.Credential, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return nil, nil, fmt.Errorf("passkey: unmarshal session: %w", err)
	}

	// The handler resolves the user from the credential's userHandle.
	var resolvedUser *storage.User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		// userHandle is the WebAuthnID which is the user's storage ID.
		userID := string(userHandle)
		user, err := s.store.GetUser(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("passkey: get user by handle: %w", err)
		}
		resolvedUser = user

		creds, err := s.store.ListCredentialsByUser(ctx, user.ID, "passkey")
		if err != nil {
			return nil, fmt.Errorf("passkey: list credentials: %w", err)
		}

		return NewUserAdapter(user, creds), nil
	}

	credential, err := s.wan.FinishDiscoverableLogin(handler, session, response)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: finish discoverable login: %w", err)
	}

	if resolvedUser == nil {
		return nil, nil, fmt.Errorf("passkey: user not resolved")
	}

	// Update sign count.
	storageCred, err := s.store.GetCredentialByCredentialID(ctx, credential.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: find credential: %w", err)
	}

	now := time.Now().UTC()
	if err := s.store.UpdateCredentialSignCount(ctx, storageCred.ID, credential.Authenticator.SignCount, now); err != nil {
		return nil, nil, fmt.Errorf("passkey: update sign count: %w", err)
	}

	storageCred.SignCount = credential.Authenticator.SignCount
	storageCred.LastUsedAt = &now

	return resolvedUser, storageCred, nil
}

// buildOrigins constructs plausible origins from an RP ID for both https and
// localhost dev.
func buildOrigins(rpID string) []string {
	origins := []string{
		"https://" + rpID,
	}
	// Allow localhost for development.
	if rpID == "localhost" {
		origins = append(origins,
			"http://localhost",
			"http://localhost:8080",
			"http://localhost:3000",
		)
	}
	return origins
}
