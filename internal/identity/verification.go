package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/webhook"
)

const (
	// TokenTypeEmailVerification is the type for email verification tokens.
	TokenTypeEmailVerification = "email_verification" // #nosec G101 -- false positive: not hardcoded credentials
	// TokenTypePasswordReset is the type for password reset tokens.
	TokenTypePasswordReset = "password_reset" // #nosec G101 -- false positive: not hardcoded credentials

	emailVerificationTTL = 24 * time.Hour
	passwordResetTTL     = 1 * time.Hour

	tokenByteLen = 32
)

// Errors returned by the verification service.
var (
	ErrTokenExpired  = errors.New("verification: token has expired")
	ErrTokenUsed     = errors.New("verification: token has already been used")
	ErrTokenInvalid  = errors.New("verification: invalid token")
	ErrPasswordShort = errors.New("verification: password must be at least 8 characters")
)

// VerificationService handles email verification and password reset flows.
type VerificationService struct {
	store   storage.Storage
	emitter *webhook.Emitter
	hasher  crypto.Hasher
}

// NewVerificationService creates a new VerificationService.
func NewVerificationService(store storage.Storage, emitter *webhook.Emitter) *VerificationService {
	return &VerificationService{
		store:   store,
		emitter: emitter,
		hasher:  crypto.NewArgon2idHasher(),
	}
}

// RequestEmailVerification generates a verification token for the given user
// and emits a webhook event with the raw token. Returns the raw token string.
func (s *VerificationService) RequestEmailVerification(ctx context.Context, userID string) (string, error) {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("verification: get user: %w", err)
	}

	rawToken, tokenHash, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("verification: generate token: %w", err)
	}

	now := time.Now().UTC()
	vt := &storage.VerificationToken{
		ID:        generateID(),
		UserID:    userID,
		Type:      TokenTypeEmailVerification,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(emailVerificationTTL),
		CreatedAt: now,
	}

	if err := s.store.CreateVerificationToken(ctx, vt); err != nil {
		return "", fmt.Errorf("verification: create token: %w", err)
	}

	s.emitter.Emit(ctx, "user.email_verification_requested", map[string]string{
		"user_id": userID,
		"email":   user.Email,
		"token":   rawToken,
	})

	return rawToken, nil
}

// VerifyEmail validates the token and marks the user's email as verified.
func (s *VerificationService) VerifyEmail(ctx context.Context, token string) error {
	vt, err := s.lookupToken(ctx, token, TokenTypeEmailVerification)
	if err != nil {
		return err
	}

	// Mark token as used.
	if err := s.store.MarkTokenUsed(ctx, vt.ID); err != nil {
		return fmt.Errorf("verification: mark used: %w", err)
	}

	// Set email_verified = true.
	user, err := s.store.GetUser(ctx, vt.UserID)
	if err != nil {
		return fmt.Errorf("verification: get user: %w", err)
	}
	user.EmailVerified = true
	if err := s.store.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("verification: update user: %w", err)
	}

	return nil
}

// RequestPasswordReset generates a password reset token for the user with the
// given email and emits a webhook event. Returns nil even if the email is not
// found to prevent user enumeration.
func (s *VerificationService) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil // silent — do not reveal whether the email exists
		}
		return fmt.Errorf("verification: get user by email: %w", err)
	}

	rawToken, tokenHash, err := generateToken()
	if err != nil {
		return fmt.Errorf("verification: generate token: %w", err)
	}

	now := time.Now().UTC()
	vt := &storage.VerificationToken{
		ID:        generateID(),
		UserID:    user.ID,
		Type:      TokenTypePasswordReset,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(passwordResetTTL),
		CreatedAt: now,
	}

	if err := s.store.CreateVerificationToken(ctx, vt); err != nil {
		return fmt.Errorf("verification: create token: %w", err)
	}

	s.emitter.Emit(ctx, "user.password_reset_requested", map[string]string{
		"user_id": user.ID,
		"email":   user.Email,
		"token":   rawToken,
	})

	return nil
}

// ResetPassword validates the token and sets a new password for the user.
func (s *VerificationService) ResetPassword(ctx context.Context, token string, newPassword string) error {
	if len(newPassword) < 8 {
		return ErrPasswordShort
	}

	vt, err := s.lookupToken(ctx, token, TokenTypePasswordReset)
	if err != nil {
		return err
	}

	// Hash the new password.
	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("verification: hash password: %w", err)
	}

	// Delete existing password credentials and create a new one.
	if err := s.store.DeleteCredentialsByUserAndType(ctx, vt.UserID, "password"); err != nil {
		return fmt.Errorf("verification: delete old credentials: %w", err)
	}

	now := time.Now().UTC()
	cred := &storage.Credential{
		ID:        generateID(),
		UserID:    vt.UserID,
		Type:      "password",
		Secret:    []byte(hash),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.CreateCredential(ctx, cred); err != nil {
		return fmt.Errorf("verification: create credential: %w", err)
	}

	// Mark token as used.
	if err := s.store.MarkTokenUsed(ctx, vt.ID); err != nil {
		return fmt.Errorf("verification: mark used: %w", err)
	}

	return nil
}

// lookupToken finds and validates a verification token.
func (s *VerificationService) lookupToken(ctx context.Context, rawToken string, expectedType string) (*storage.VerificationToken, error) {
	hash := hashToken(rawToken)
	vt, err := s.store.GetVerificationTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrTokenInvalid
		}
		return nil, fmt.Errorf("verification: get token: %w", err)
	}

	if vt.Type != expectedType {
		return nil, ErrTokenInvalid
	}

	if vt.UsedAt != nil {
		return nil, ErrTokenUsed
	}

	if time.Now().UTC().After(vt.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return vt, nil
}

// generateToken creates a cryptographically random token and its SHA-256 hash.
func generateToken() (raw string, hash string, err error) {
	b := make([]byte, tokenByteLen)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.URLEncoding.EncodeToString(b)
	hash = hashToken(raw)
	return raw, hash, nil
}

// hashToken returns the hex-encoded SHA-256 hash of a raw token string.
func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:])
}

// generateID creates a unique ID.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
