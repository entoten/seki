package password

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/validate"
)

const credentialType = "password"

// Errors returned by the password service.
var (
	ErrPasswordTooShort = errors.New("password: must be at least 8 characters")
	ErrPasswordTooLong  = errors.New("password: exceeds maximum length")
	ErrNotConfigured    = errors.New("password: not configured for user")
	ErrInvalidPassword  = errors.New("password: invalid password")
)

// Service provides password registration and verification.
type Service struct {
	hasher crypto.Hasher
	store  storage.Storage
}

// NewService creates a new password service using argon2id hashing.
func NewService(store storage.Storage) *Service {
	return &Service{
		hasher: crypto.NewArgon2idHasher(),
		store:  store,
	}
}

// Register creates a password credential for the given user.
// The password must be at least 8 characters long.
func (s *Service) Register(ctx context.Context, userID string, password string) error {
	if len(password) < validate.MinPasswordLen {
		return ErrPasswordTooShort
	}
	if len(password) > validate.MaxPasswordLen {
		return ErrPasswordTooLong
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return fmt.Errorf("password: hash: %w", err)
	}

	now := time.Now().UTC()
	cred := &storage.Credential{
		ID:        generateID(),
		UserID:    userID,
		Type:      credentialType,
		Secret:    []byte(hash),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.CreateCredential(ctx, cred); err != nil {
		return fmt.Errorf("password: create credential: %w", err)
	}
	return nil
}

// Verify checks the provided password against the stored hash for the user.
func (s *Service) Verify(ctx context.Context, userID string, password string) error {
	creds, err := s.store.GetCredentialsByUserAndType(ctx, userID, credentialType)
	if err != nil {
		return fmt.Errorf("password: get credentials: %w", err)
	}
	if len(creds) == 0 {
		return ErrNotConfigured
	}

	storedHash := string(creds[0].Secret)
	if err := s.hasher.Verify(password, storedHash); err != nil {
		return ErrInvalidPassword
	}

	return nil
}

// ChangePassword verifies the old password and replaces it with the new one.
func (s *Service) ChangePassword(ctx context.Context, userID string, oldPassword, newPassword string) error {
	if len(newPassword) < validate.MinPasswordLen {
		return ErrPasswordTooShort
	}
	if len(newPassword) > validate.MaxPasswordLen {
		return ErrPasswordTooLong
	}

	creds, err := s.store.GetCredentialsByUserAndType(ctx, userID, credentialType)
	if err != nil {
		return fmt.Errorf("password: get credentials: %w", err)
	}
	if len(creds) == 0 {
		return ErrNotConfigured
	}

	storedHash := string(creds[0].Secret)
	if err := s.hasher.Verify(oldPassword, storedHash); err != nil {
		return ErrInvalidPassword
	}

	newHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("password: hash new password: %w", err)
	}

	cred := creds[0]
	cred.Secret = []byte(newHash)
	cred.UpdatedAt = time.Now().UTC()

	if err := s.store.UpdateCredential(ctx, cred); err != nil {
		return fmt.Errorf("password: update credential: %w", err)
	}

	return nil
}

// RemovePassword deletes the password credential for the user.
func (s *Service) RemovePassword(ctx context.Context, userID string) error {
	if err := s.store.DeleteCredentialsByUserAndType(ctx, userID, credentialType); err != nil {
		return fmt.Errorf("password: remove: %w", err)
	}
	return nil
}

// generateID creates a unique ID for credentials.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
