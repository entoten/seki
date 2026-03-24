package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// dpopMaxClockSkew is the maximum allowed age for DPoP proof iat claims.
const dpopMaxClockSkew = 5 * time.Minute

// dpopNonceStore tracks used jti values to prevent replay attacks.
// Entries expire after dpopMaxClockSkew to bound memory usage.
type dpopNonceStore struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	lastGC  time.Time
	gcEvery time.Duration
}

func newDPoPNonceStore() *dpopNonceStore {
	return &dpopNonceStore{
		seen:    make(map[string]time.Time),
		lastGC:  time.Now(),
		gcEvery: time.Minute,
	}
}

// checkAndStore returns true if jti was already seen (replay). Otherwise it stores it.
func (s *dpopNonceStore) checkAndStore(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Garbage-collect old entries periodically.
	now := time.Now()
	if now.Sub(s.lastGC) > s.gcEvery {
		cutoff := now.Add(-dpopMaxClockSkew - time.Minute)
		for k, t := range s.seen {
			if t.Before(cutoff) {
				delete(s.seen, k)
			}
		}
		s.lastGC = now
	}

	if _, exists := s.seen[jti]; exists {
		return true // replay
	}
	s.seen[jti] = now
	return false
}

// DPoPProof holds the validated fields from a DPoP proof JWT.
type DPoPProof struct {
	// JKT is the base64url-encoded SHA-256 thumbprint of the client's public key.
	JKT string
}

// dpopResult represents the outcome of DPoP header processing on the token endpoint.
type dpopResult struct {
	// present indicates whether a DPoP header was provided.
	present bool
	// jkt is the JWK thumbprint, set only when present && valid.
	jkt string
}

// validateDPoP checks the DPoP header on a request, if present.
// It returns the dpopResult indicating whether DPoP was used and the key thumbprint.
// If the header is present but invalid, it returns an error.
func (p *Provider) validateDPoP(r *http.Request, httpMethod, httpURI string) (*dpopResult, error) {
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return &dpopResult{present: false}, nil
	}

	proof, err := p.parseDPoPProof(dpopHeader, httpMethod, httpURI)
	if err != nil {
		return nil, err
	}

	return &dpopResult{present: true, jkt: proof.JKT}, nil
}

// parseDPoPProof parses and validates a DPoP proof JWT per RFC 9449.
func (p *Provider) parseDPoPProof(proofJWT, expectedHTM, expectedHTU string) (*DPoPProof, error) {
	// Parse without verification first to inspect the header.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, parts, err := parser.ParseUnverified(proofJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("dpop: failed to parse proof: %w", err)
	}
	_ = parts

	// Validate typ header.
	typ, _ := token.Header["typ"].(string)
	if !strings.EqualFold(typ, "dpop+jwt") {
		return nil, errors.New("dpop: typ header must be dpop+jwt")
	}

	// Extract JWK from header.
	jwkRaw, ok := token.Header["jwk"]
	if !ok {
		return nil, errors.New("dpop: missing jwk header")
	}

	// Must not have kid header (RFC 9449 section 4.2).
	if _, hasKID := token.Header["kid"]; hasKID {
		return nil, errors.New("dpop: kid header must not be present")
	}

	jwkBytes, err := json.Marshal(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("dpop: failed to marshal jwk: %w", err)
	}

	pubKey, alg, err := parseJWK(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}

	// Verify the algorithm matches the header.
	headerAlg, _ := token.Header["alg"].(string)
	if headerAlg != alg {
		return nil, fmt.Errorf("dpop: alg header %q does not match jwk algorithm %q", headerAlg, alg)
	}

	// Now verify the signature properly.
	signingMethod := jwt.GetSigningMethod(headerAlg)
	if signingMethod == nil {
		return nil, fmt.Errorf("dpop: unsupported signing algorithm: %s", headerAlg)
	}

	// Re-parse with proper verification.
	verifiedToken, err := jwt.Parse(proofJWT, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}, jwt.WithValidMethods([]string{alg}))
	if err != nil {
		return nil, fmt.Errorf("dpop: signature verification failed: %w", err)
	}

	claims, ok := verifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("dpop: unexpected claims type")
	}

	// Validate htm (HTTP method).
	htm, _ := claims["htm"].(string)
	if !strings.EqualFold(htm, expectedHTM) {
		return nil, fmt.Errorf("dpop: htm %q does not match expected %q", htm, expectedHTM)
	}

	// Validate htu (HTTP URI).
	htu, _ := claims["htu"].(string)
	if htu != expectedHTU {
		return nil, fmt.Errorf("dpop: htu %q does not match expected %q", htu, expectedHTU)
	}

	// Validate jti.
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New("dpop: missing jti claim")
	}

	// Check jti uniqueness.
	if p.dpopNonces.checkAndStore(jti) {
		return nil, errors.New("dpop: jti has already been used (replay)")
	}

	// Validate iat.
	iatRaw, ok := claims["iat"]
	if !ok {
		return nil, errors.New("dpop: missing iat claim")
	}
	iatFloat, ok := iatRaw.(float64)
	if !ok {
		return nil, errors.New("dpop: iat claim is not a number")
	}
	iat := time.Unix(int64(iatFloat), 0)
	now := time.Now()
	if now.Sub(iat) > dpopMaxClockSkew {
		return nil, errors.New("dpop: iat is too old")
	}
	if iat.After(now.Add(dpopMaxClockSkew)) {
		return nil, errors.New("dpop: iat is in the future")
	}

	// Compute JWK thumbprint per RFC 7638.
	jkt, err := computeJWKThumbprint(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("dpop: failed to compute jwk thumbprint: %w", err)
	}

	return &DPoPProof{JKT: jkt}, nil
}

// parseJWK parses a JWK JSON and returns the public key and algorithm.
func parseJWK(jwkJSON []byte) (crypto.PublicKey, string, error) {
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, "", fmt.Errorf("invalid jwk: %w", err)
	}

	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		return parseECJWK(jwk)
	case "OKP":
		return parseOKPJWK(jwk)
	default:
		return nil, "", fmt.Errorf("unsupported jwk key type: %s", kty)
	}
}

// parseECJWK parses an EC JWK and returns the ECDSA public key.
func parseECJWK(jwk map[string]interface{}) (crypto.PublicKey, string, error) {
	crv, _ := jwk["crv"].(string)
	if crv != "P-256" {
		return nil, "", fmt.Errorf("unsupported EC curve: %s", crv)
	}

	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)
	if xStr == "" || yStr == "" {
		return nil, "", errors.New("missing x or y in EC jwk")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, "", fmt.Errorf("decoding x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, "", fmt.Errorf("decoding y: %w", err)
	}

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	return pub, "ES256", nil
}

// parseOKPJWK parses an OKP JWK (Ed25519) and returns the public key.
func parseOKPJWK(jwk map[string]interface{}) (crypto.PublicKey, string, error) {
	crv, _ := jwk["crv"].(string)
	if crv != "Ed25519" {
		return nil, "", fmt.Errorf("unsupported OKP curve: %s", crv)
	}

	xStr, _ := jwk["x"].(string)
	if xStr == "" {
		return nil, "", errors.New("missing x in OKP jwk")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, "", fmt.Errorf("decoding x: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("invalid Ed25519 public key size: %d", len(xBytes))
	}

	return ed25519.PublicKey(xBytes), "EdDSA", nil
}

// computeJWKThumbprint computes the JWK thumbprint per RFC 7638.
// The thumbprint is the base64url-encoded SHA-256 hash of the canonical JWK representation.
func computeJWKThumbprint(jwkJSON []byte) (string, error) {
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return "", err
	}

	kty, _ := jwk["kty"].(string)

	// Build the canonical JSON per RFC 7638 (members in lexicographic order).
	var canonical []byte
	var err error

	switch kty {
	case "EC":
		canonical, err = json.Marshal(map[string]interface{}{
			"crv": jwk["crv"],
			"kty": jwk["kty"],
			"x":   jwk["x"],
			"y":   jwk["y"],
		})
	case "OKP":
		canonical, err = json.Marshal(map[string]interface{}{
			"crv": jwk["crv"],
			"kty": jwk["kty"],
			"x":   jwk["x"],
		})
	default:
		return "", fmt.Errorf("unsupported kty for thumbprint: %s", kty)
	}

	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
