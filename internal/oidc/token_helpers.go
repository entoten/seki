package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Monet/seki/internal/storage"
)

// generateAccessToken creates a signed JWT access token.
func (p *Provider) generateAccessToken(sub, clientID string, scopes []string, now time.Time) (string, error) {
	claims := map[string]interface{}{
		"sub":   sub,
		"aud":   clientID,
		"scope": strings.Join(scopes, " "),
		"iat":   now.Unix(),
		"exp":   now.Add(accessTokenTTL).Unix(),
		"iss":   p.issuer,
		"typ":   "access_token",
	}
	return p.signer.Sign(claims)
}

// generateIDToken creates a signed JWT ID token with OIDC standard claims.
// The acr parameter sets the Authentication Context Class Reference claim.
// If empty, it defaults to ACRBasic.
func (p *Provider) generateIDToken(user *storage.User, client *storage.Client, nonce string, acr string, now time.Time) (string, error) {
	if acr == "" {
		acr = ACRBasic
	}
	claims := map[string]interface{}{
		"sub": user.ID,
		"iss": p.issuer,
		"aud": client.ID,
		"exp": now.Add(accessTokenTTL).Unix(),
		"iat": now.Unix(),
		"acr": acr,
	}

	if user.Email != "" {
		claims["email"] = user.Email
	}
	if user.DisplayName != "" {
		claims["name"] = user.DisplayName
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	return p.signer.Sign(claims)
}

// generateRefreshToken creates a cryptographically random opaque refresh token.
func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns the hex-encoded SHA-256 hash of a token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// generateFamily creates a random family identifier for refresh token rotation tracking.
func generateFamily() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// generateTokenID creates a random token ID.
func generateTokenID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// bcryptCompare compares a bcrypt hash with a plaintext password.
func bcryptCompare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
