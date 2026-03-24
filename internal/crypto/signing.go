package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Signer provides JWT signing and verification using a cryptographic key pair.
type Signer interface {
	// Sign creates a signed JWT from the given claims map.
	Sign(claims map[string]interface{}) (string, error)
	// Verify parses and validates a JWT, returning the claims.
	Verify(tokenString string) (map[string]interface{}, error)
	// PublicKeyJWK returns the public key in JWK format for the JWKS endpoint.
	PublicKeyJWK() map[string]interface{}
	// Algorithm returns the signing algorithm identifier (e.g., "EdDSA").
	Algorithm() string
	// KeyID returns the key identifier used in the JWT header.
	KeyID() string
}

// Ed25519Signer implements Signer using Ed25519 keys and the EdDSA algorithm.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	issuer     string
	tokenTTL   time.Duration
}

// Ed25519SignerOptions holds configuration for creating an Ed25519Signer.
type Ed25519SignerOptions struct {
	// KeyFile is the path to a PEM-encoded Ed25519 private key.
	// If empty or the file does not exist, a new key pair is generated.
	KeyFile  string
	KeyID    string
	Issuer   string
	TokenTTL time.Duration
}

// NewEd25519Signer creates a new Ed25519Signer. It attempts to load the key
// from KeyFile. If the file does not exist, it generates a new key pair and
// writes it to KeyFile (if KeyFile is non-empty).
func NewEd25519Signer(opts Ed25519SignerOptions) (*Ed25519Signer, error) {
	var privKey ed25519.PrivateKey
	var pubKey ed25519.PublicKey

	if opts.KeyFile != "" {
		data, err := os.ReadFile(opts.KeyFile)
		if err == nil {
			privKey, err = parseEd25519PrivateKeyPEM(data)
			if err != nil {
				return nil, fmt.Errorf("parsing key file %s: %w", opts.KeyFile, err)
			}
			pubKey = privKey.Public().(ed25519.PublicKey)
		} else if errors.Is(err, os.ErrNotExist) {
			// Auto-generate key and persist it.
			pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("generating ed25519 key: %w", err)
			}
			if err := writeEd25519PrivateKeyPEM(opts.KeyFile, privKey); err != nil {
				return nil, fmt.Errorf("writing generated key to %s: %w", opts.KeyFile, err)
			}
		} else {
			return nil, fmt.Errorf("reading key file %s: %w", opts.KeyFile, err)
		}
	} else {
		// No file path; generate an ephemeral key.
		var err error
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ed25519 key: %w", err)
		}
	}

	keyID := opts.KeyID
	if keyID == "" {
		keyID = "seki-ed25519-1"
	}

	ttl := opts.TokenTTL
	if ttl == 0 {
		ttl = time.Hour
	}

	return &Ed25519Signer{
		privateKey: privKey,
		publicKey:  pubKey,
		keyID:      keyID,
		issuer:     opts.Issuer,
		tokenTTL:   ttl,
	}, nil
}

// NewEd25519SignerFromKey creates a signer directly from an existing key pair.
func NewEd25519SignerFromKey(privKey ed25519.PrivateKey, keyID, issuer string, ttl time.Duration) *Ed25519Signer {
	if keyID == "" {
		keyID = "seki-ed25519-1"
	}
	if ttl == 0 {
		ttl = time.Hour
	}
	return &Ed25519Signer{
		privateKey: privKey,
		publicKey:  privKey.Public().(ed25519.PublicKey),
		keyID:      keyID,
		issuer:     issuer,
		tokenTTL:   ttl,
	}
}

// Sign creates a signed JWT with the given additional claims. Standard claims
// (iss, iat, exp, kid) are added automatically.
func (s *Ed25519Signer) Sign(claims map[string]interface{}) (string, error) {
	now := time.Now()

	mapClaims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(s.tokenTTL).Unix(),
	}

	if s.issuer != "" {
		mapClaims["iss"] = s.issuer
	}

	// Merge caller-provided claims; caller can override iss/iat/exp if needed.
	for k, v := range claims {
		mapClaims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, mapClaims)
	token.Header["kid"] = s.keyID

	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return signed, nil
}

// Verify parses and validates the given JWT string, returning the claims.
func (s *Ed25519Signer) Verify(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unexpected claims type")
	}

	result := make(map[string]interface{}, len(mapClaims))
	for k, v := range mapClaims {
		result[k] = v
	}

	return result, nil
}

// PublicKeyJWK returns the public key in JWK format suitable for a JWKS
// endpoint (/.well-known/jwks.json).
func (s *Ed25519Signer) PublicKeyJWK() map[string]interface{} {
	return map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"alg": "EdDSA",
		"use": "sig",
		"kid": s.keyID,
		"x":   base64.RawURLEncoding.EncodeToString(s.publicKey),
	}
}

// Algorithm returns the JWT algorithm identifier.
func (s *Ed25519Signer) Algorithm() string {
	return "EdDSA"
}

// KeyID returns the key identifier.
func (s *Ed25519Signer) KeyID() string {
	return s.keyID
}

// parseEd25519PrivateKeyPEM decodes a PEM-encoded Ed25519 private key.
func parseEd25519PrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ed25519, got %T", key)
	}

	return edKey, nil
}

// KeySet holds multiple signing keys to support key rotation.
// The current key is used for signing new tokens; all keys are published
// in the JWKS endpoint and can be used for verification.
type KeySet struct {
	keys    []Signer
	current int // index of current signing key
}

// NewKeySet creates a KeySet from one or more signers. The first signer is the
// current signing key; subsequent signers are old (rotated) keys kept for
// verification of previously-issued tokens.
func NewKeySet(signers ...Signer) *KeySet {
	return &KeySet{
		keys:    signers,
		current: 0,
	}
}

// Current returns the active signing key used for new tokens.
func (ks *KeySet) Current() Signer {
	return ks.keys[ks.current]
}

// AllPublicKeys returns the JWK representations of every key in the set,
// suitable for the JWKS endpoint.
func (ks *KeySet) AllPublicKeys() []map[string]interface{} {
	result := make([]map[string]interface{}, len(ks.keys))
	for i, k := range ks.keys {
		result[i] = k.PublicKeyJWK()
	}
	return result
}

// VerifyAny attempts to verify the given token against all keys in the set,
// trying the current key first. It returns the claims from the first successful
// verification, or the last error if all keys fail.
func (ks *KeySet) VerifyAny(token string) (map[string]interface{}, error) {
	// Try current key first.
	claims, err := ks.keys[ks.current].Verify(token)
	if err == nil {
		return claims, nil
	}

	var lastErr error = err
	for i, k := range ks.keys {
		if i == ks.current {
			continue
		}
		claims, err := k.Verify(token)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Sign delegates to the current key's Sign method.
func (ks *KeySet) Sign(claims map[string]interface{}) (string, error) {
	return ks.keys[ks.current].Sign(claims)
}

// Verify tries all keys using VerifyAny. This implements the Signer interface.
func (ks *KeySet) Verify(tokenString string) (map[string]interface{}, error) {
	return ks.VerifyAny(tokenString)
}

// PublicKeyJWK returns the current key's JWK. For the full set, use AllPublicKeys.
func (ks *KeySet) PublicKeyJWK() map[string]interface{} {
	return ks.keys[ks.current].PublicKeyJWK()
}

// Algorithm returns the current key's algorithm.
func (ks *KeySet) Algorithm() string {
	return ks.keys[ks.current].Algorithm()
}

// KeyID returns the current key's identifier.
func (ks *KeySet) KeyID() string {
	return ks.keys[ks.current].KeyID()
}

// writeEd25519PrivateKeyPEM marshals and writes an Ed25519 private key in PEM format.
func writeEd25519PrivateKeyPEM(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}
