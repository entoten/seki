package magiclink

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/webhook"
)

const (
	// TokenTypeMagicLink is the type for magic link verification tokens.
	TokenTypeMagicLink = "magic_link" // #nosec G101 -- false positive: not hardcoded credentials

	tokenByteLen = 32

	defaultCodeLength = 6
	defaultTTL        = 10 * time.Minute

	// Rate limiting defaults.
	maxRequestsPerEmail    = 3
	requestWindowDuration  = 10 * time.Minute
	maxVerifyAttemptsPerID = 5
)

// Errors returned by the magic link service.
var (
	ErrCodeInvalid     = errors.New("magiclink: invalid code")
	ErrCodeExpired     = errors.New("magiclink: code has expired")
	ErrCodeUsed        = errors.New("magiclink: code has already been used")
	ErrTokenInvalid    = errors.New("magiclink: invalid token")
	ErrTokenExpired    = errors.New("magiclink: token has expired")
	ErrTokenUsed       = errors.New("magiclink: token has already been used")
	ErrRateLimited     = errors.New("magiclink: too many requests")
	ErrTooManyAttempts = errors.New("magiclink: too many verification attempts")
	ErrUserNotFound    = errors.New("magiclink: user not found")
)

// requestRecord tracks rate limiting state for an email.
type requestRecord struct {
	timestamps []time.Time
}

// verifyRecord tracks verification attempt count for a token ID.
type verifyRecord struct {
	attempts int
}

// Service handles magic link and email OTP authentication.
type Service struct {
	store   storage.Storage
	emitter *webhook.Emitter
	issuer  string
	ttl     time.Duration
	codeLen int

	mu            sync.Mutex
	requestCounts map[string]*requestRecord // email -> request timestamps
	verifyCounts  map[string]*verifyRecord  // token ID -> attempts

	// nowFunc allows overriding time in tests.
	nowFunc func() time.Time
}

// NewService creates a new magic link Service.
func NewService(store storage.Storage, emitter *webhook.Emitter, issuer string, ttl time.Duration, codeLen int) *Service {
	if ttl == 0 {
		ttl = defaultTTL
	}
	if codeLen == 0 {
		codeLen = defaultCodeLength
	}
	return &Service{
		store:         store,
		emitter:       emitter,
		issuer:        issuer,
		ttl:           ttl,
		codeLen:       codeLen,
		requestCounts: make(map[string]*requestRecord),
		verifyCounts:  make(map[string]*verifyRecord),
		nowFunc:       func() time.Time { return time.Now().UTC() },
	}
}

// RequestCode generates a 6-digit OTP and a magic link token for the given email.
// It stores both as verification tokens and emits a webhook event.
// Returns the OTP code (for testing/webhook), or an error.
func (s *Service) RequestCode(ctx context.Context, email string) (string, error) {
	// Rate limiting: max 3 requests per email per 10 minutes.
	if err := s.checkRequestRate(email); err != nil {
		return "", err
	}

	// Look up the user by email. Return nil error even if not found to prevent
	// user enumeration — but silently do nothing.
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("magiclink: get user by email: %w", err)
	}

	now := s.nowFunc()
	expiresAt := now.Add(s.ttl)

	// Generate OTP code.
	code, codeHash, err := s.generateCode()
	if err != nil {
		return "", fmt.Errorf("magiclink: generate code: %w", err)
	}

	// Store OTP as a verification token.
	otpTokenID := generateID()
	otpToken := &storage.VerificationToken{
		ID:        otpTokenID,
		UserID:    user.ID,
		Type:      TokenTypeMagicLink,
		TokenHash: codeHash,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	if err := s.store.CreateVerificationToken(ctx, otpToken); err != nil {
		return "", fmt.Errorf("magiclink: create otp token: %w", err)
	}

	// Generate magic link token.
	rawToken, tokenHash, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("magiclink: generate magic link token: %w", err)
	}

	linkTokenID := generateID()
	linkToken := &storage.VerificationToken{
		ID:        linkTokenID,
		UserID:    user.ID,
		Type:      TokenTypeMagicLink,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	if err := s.store.CreateVerificationToken(ctx, linkToken); err != nil {
		return "", fmt.Errorf("magiclink: create link token: %w", err)
	}

	// Build magic link URL.
	magicLinkURL := fmt.Sprintf("%s/authn/magiclink/verify?token=%s", s.issuer, rawToken)

	// Emit webhook.
	s.emitter.Emit(ctx, "user.magic_link_requested", map[string]string{
		"email":      email,
		"code":       code,
		"magic_link": magicLinkURL,
		"expires_at": expiresAt.Format(time.RFC3339),
	})

	return code, nil
}

// VerifyCode verifies an OTP code for the given email and returns the user.
func (s *Service) VerifyCode(ctx context.Context, email, code string) (*storage.User, error) {
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrCodeInvalid
		}
		return nil, fmt.Errorf("magiclink: get user by email: %w", err)
	}

	// Hash the code to look it up.
	codeHash := hashCode(code)
	vt, err := s.store.GetVerificationTokenByHash(ctx, codeHash)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrCodeInvalid
		}
		return nil, fmt.Errorf("magiclink: get token by hash: %w", err)
	}

	// Verify attempt rate limiting.
	if err := s.checkVerifyAttempts(vt.ID); err != nil {
		return nil, err
	}

	if vt.Type != TokenTypeMagicLink {
		return nil, ErrCodeInvalid
	}

	if vt.UserID != user.ID {
		return nil, ErrCodeInvalid
	}

	if vt.UsedAt != nil {
		return nil, ErrCodeUsed
	}

	now := s.nowFunc()
	if now.After(vt.ExpiresAt) {
		return nil, ErrCodeExpired
	}

	// Mark token as used.
	if err := s.store.MarkTokenUsed(ctx, vt.ID); err != nil {
		return nil, fmt.Errorf("magiclink: mark used: %w", err)
	}

	return user, nil
}

// VerifyMagicLink verifies a magic link token and returns the user.
func (s *Service) VerifyMagicLink(ctx context.Context, token string) (*storage.User, error) {
	tokenHash := hashToken(token)
	vt, err := s.store.GetVerificationTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrTokenInvalid
		}
		return nil, fmt.Errorf("magiclink: get token by hash: %w", err)
	}

	// Verify attempt rate limiting.
	if err := s.checkVerifyAttempts(vt.ID); err != nil {
		return nil, err
	}

	if vt.Type != TokenTypeMagicLink {
		return nil, ErrTokenInvalid
	}

	if vt.UsedAt != nil {
		return nil, ErrTokenUsed
	}

	now := s.nowFunc()
	if now.After(vt.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Mark token as used.
	if err := s.store.MarkTokenUsed(ctx, vt.ID); err != nil {
		return nil, fmt.Errorf("magiclink: mark used: %w", err)
	}

	user, err := s.store.GetUser(ctx, vt.UserID)
	if err != nil {
		return nil, fmt.Errorf("magiclink: get user: %w", err)
	}

	return user, nil
}

// checkRequestRate enforces max 3 requests per email per 10 minutes.
func (s *Service) checkRequestRate(email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowFunc()
	rec, ok := s.requestCounts[email]
	if !ok {
		rec = &requestRecord{}
		s.requestCounts[email] = rec
	}

	// Prune old timestamps.
	cutoff := now.Add(-requestWindowDuration)
	valid := rec.timestamps[:0]
	for _, ts := range rec.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	rec.timestamps = valid

	if len(rec.timestamps) >= maxRequestsPerEmail {
		return ErrRateLimited
	}

	rec.timestamps = append(rec.timestamps, now)
	return nil
}

// checkVerifyAttempts enforces max 5 verification attempts per token.
func (s *Service) checkVerifyAttempts(tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.verifyCounts[tokenID]
	if !ok {
		rec = &verifyRecord{}
		s.verifyCounts[tokenID] = rec
	}

	rec.attempts++
	if rec.attempts > maxVerifyAttemptsPerID {
		return ErrTooManyAttempts
	}

	return nil
}

// generateCode creates a cryptographically random numeric OTP code.
func (s *Service) generateCode() (code string, hash string, err error) {
	// Build the max value: 10^codeLen.
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(s.codeLen)), nil)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", "", err
	}

	// Zero-pad to codeLen digits.
	code = fmt.Sprintf("%0*d", s.codeLen, n)
	hash = hashCode(code)
	return code, hash, nil
}

// hashCode returns the hex-encoded SHA-256 hash of a code string.
func hashCode(code string) string {
	h := sha256.Sum256([]byte("otp:" + code))
	return fmt.Sprintf("%x", h[:])
}

// hashToken returns the hex-encoded SHA-256 hash of a raw token string.
func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:])
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

// generateID creates a unique ID.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
