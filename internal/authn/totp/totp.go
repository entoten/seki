package totp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
)

const (
	credentialType    = "totp"
	recoveryCodeLen   = 8
	recoveryCodeCount = 8
	alphanumeric      = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// Errors returned by the TOTP service.
var (
	ErrInvalidCode    = errors.New("totp: invalid code")
	ErrNotConfigured  = errors.New("totp: not configured for user")
	ErrAlreadyEnabled = errors.New("totp: already enabled for user")
)

// Service provides TOTP registration and verification.
type Service struct {
	issuer string
	store  storage.Storage
}

// NewService creates a new TOTP service.
func NewService(cfg config.TOTPConfig, store storage.Storage) *Service {
	return &Service{
		issuer: cfg.Issuer,
		store:  store,
	}
}

// GenerateSecret generates a new TOTP key and recovery codes for the given user.
// The key is returned so callers can extract the otpauth URI for QR display.
// The recovery codes are returned in plaintext (for one-time display to the user).
func (s *Service) GenerateSecret(user *storage.User) (*otp.Key, []string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: user.Email,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("totp: generate key: %w", err)
	}

	codes, err := generateRecoveryCodes(recoveryCodeCount, recoveryCodeLen)
	if err != nil {
		return nil, nil, fmt.Errorf("totp: generate recovery codes: %w", err)
	}

	return key, codes, nil
}

// EnableTOTP verifies the provided code against the secret and, if valid,
// stores the TOTP credential for the user. Recovery codes must be provided
// in plaintext; they will be hashed before storage.
func (s *Service) EnableTOTP(ctx context.Context, userID string, secret string, code string, recoveryCodes []string) error {
	// Check if TOTP is already enabled.
	existing, err := s.store.GetCredentialsByUserAndType(ctx, userID, credentialType)
	if err != nil {
		return fmt.Errorf("totp: check existing: %w", err)
	}
	if len(existing) > 0 {
		return ErrAlreadyEnabled
	}

	// Verify the code against the secret before storing.
	if !totp.Validate(code, secret) {
		return ErrInvalidCode
	}

	// Hash recovery codes for storage.
	hashedCodes, err := hashRecoveryCodes(recoveryCodes)
	if err != nil {
		return fmt.Errorf("totp: hash recovery codes: %w", err)
	}

	meta, err := json.Marshal(map[string]interface{}{
		"recovery_codes": hashedCodes,
	})
	if err != nil {
		return fmt.Errorf("totp: marshal metadata: %w", err)
	}

	now := time.Now().UTC()
	cred := &storage.Credential{
		ID:        generateID(),
		UserID:    userID,
		Type:      credentialType,
		Secret:    []byte(secret),
		Metadata:  meta,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.CreateCredential(ctx, cred); err != nil {
		return fmt.Errorf("totp: create credential: %w", err)
	}
	return nil
}

// Verify checks the provided TOTP code against the stored secret for the user.
func (s *Service) Verify(ctx context.Context, userID string, code string) (bool, error) {
	creds, err := s.store.GetCredentialsByUserAndType(ctx, userID, credentialType)
	if err != nil {
		return false, fmt.Errorf("totp: get credentials: %w", err)
	}
	if len(creds) == 0 {
		return false, ErrNotConfigured
	}

	secret := string(creds[0].Secret)
	return totp.Validate(code, secret), nil
}

// VerifyRecoveryCode checks and consumes a recovery code for the user.
// If valid, the code is removed from the stored set so it cannot be reused.
func (s *Service) VerifyRecoveryCode(ctx context.Context, userID string, code string) (bool, error) {
	creds, err := s.store.GetCredentialsByUserAndType(ctx, userID, credentialType)
	if err != nil {
		return false, fmt.Errorf("totp: get credentials: %w", err)
	}
	if len(creds) == 0 {
		return false, ErrNotConfigured
	}

	cred := creds[0]

	var meta map[string]interface{}
	if err := json.Unmarshal(cred.Metadata, &meta); err != nil {
		return false, fmt.Errorf("totp: unmarshal metadata: %w", err)
	}

	rawCodes, ok := meta["recovery_codes"]
	if !ok {
		return false, nil
	}

	codesSlice, ok := rawCodes.([]interface{})
	if !ok {
		return false, nil
	}

	// Find and consume the matching recovery code.
	matchIdx := -1
	for i, hashed := range codesSlice {
		hashedStr, ok := hashed.(string)
		if !ok {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hashedStr), []byte(code)); err == nil {
			matchIdx = i
			break
		}
	}

	if matchIdx == -1 {
		return false, nil
	}

	// Remove the consumed code.
	codesSlice = append(codesSlice[:matchIdx], codesSlice[matchIdx+1:]...)
	meta["recovery_codes"] = codesSlice

	updatedMeta, err := json.Marshal(meta)
	if err != nil {
		return false, fmt.Errorf("totp: marshal updated metadata: %w", err)
	}
	cred.Metadata = updatedMeta

	if err := s.store.UpdateCredential(ctx, cred); err != nil {
		return false, fmt.Errorf("totp: update credential: %w", err)
	}

	return true, nil
}

// Disable removes the TOTP credential for the user.
func (s *Service) Disable(ctx context.Context, userID string) error {
	if err := s.store.DeleteCredentialsByUserAndType(ctx, userID, credentialType); err != nil {
		return fmt.Errorf("totp: disable: %w", err)
	}
	return nil
}

// generateRecoveryCodes creates n random alphanumeric codes of the given length.
func generateRecoveryCodes(n, length int) ([]string, error) {
	codes := make([]string, n)
	for i := 0; i < n; i++ {
		code, err := randomString(length)
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

// hashRecoveryCodes hashes each recovery code with bcrypt.
func hashRecoveryCodes(codes []string) ([]string, error) {
	hashed := make([]string, len(codes))
	for i, code := range codes {
		h, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		hashed[i] = string(h)
	}
	return hashed, nil
}

// randomString generates a cryptographically random alphanumeric string.
func randomString(length int) (string, error) {
	max := big.NewInt(int64(len(alphanumeric)))
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		buf[i] = alphanumeric[n.Int64()]
	}
	return string(buf), nil
}

// generateID creates a unique ID for credentials.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
