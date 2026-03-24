package pat

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Monet/seki/internal/storage"
)

const (
	// Prefix identifies personal access tokens in logs and grep.
	Prefix = "seki_pat_"
	// tokenBytes is the number of random bytes in a PAT.
	tokenBytes = 32
)

// Errors returned by the PAT service.
var (
	ErrInvalidToken = errors.New("pat: invalid token")
	ErrExpired      = errors.New("pat: token expired")
)

// Service manages personal access tokens.
type Service struct {
	store storage.PATStore
}

// NewService creates a new PAT service.
func NewService(store storage.PATStore) *Service {
	return &Service{store: store}
}

// Generate creates a new personal access token for the given user.
// It returns the raw token (shown once) and the stored PAT record.
func (s *Service) Generate(ctx context.Context, userID, name string, scopes []string, expiresAt time.Time) (string, *storage.PersonalAccessToken, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("pat: generate random: %w", err)
	}

	rawToken := Prefix + base64.RawURLEncoding.EncodeToString(b)
	hash := HashToken(rawToken)

	now := time.Now().UTC().Truncate(time.Second)
	if scopes == nil {
		scopes = []string{}
	}

	pat := &storage.PersonalAccessToken{
		ID:        generateID(),
		UserID:    userID,
		Name:      name,
		TokenHash: hash,
		Scopes:    scopes,
		ExpiresAt: expiresAt.UTC().Truncate(time.Second),
		CreatedAt: now,
	}

	if err := s.store.CreatePAT(ctx, pat); err != nil {
		return "", nil, fmt.Errorf("pat: create: %w", err)
	}

	return rawToken, pat, nil
}

// Validate checks a raw token, looks it up, verifies expiry, and updates last_used_at.
func (s *Service) Validate(ctx context.Context, token string) (*storage.PersonalAccessToken, error) {
	if !strings.HasPrefix(token, Prefix) {
		return nil, ErrInvalidToken
	}

	hash := HashToken(token)
	pat, err := s.store.GetPATByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("pat: lookup: %w", err)
	}

	if time.Now().UTC().After(pat.ExpiresAt) {
		return nil, ErrExpired
	}

	// Update last_used_at asynchronously is acceptable, but for simplicity we do it inline.
	now := time.Now().UTC().Truncate(time.Second)
	_ = s.store.UpdatePATLastUsed(ctx, pat.ID, now)
	pat.LastUsedAt = &now

	return pat, nil
}

// Revoke deletes a personal access token by ID.
func (s *Service) Revoke(ctx context.Context, patID string) error {
	return s.store.DeletePAT(ctx, patID)
}

// HashToken returns the hex-encoded SHA-256 hash of a token string.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// generateID creates a random ID for a PAT.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
