package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Hasher provides password hashing and verification.
type Hasher interface {
	// Hash returns a hashed representation of the password.
	Hash(password string) (string, error)
	// Verify checks whether password matches the given hash.
	Verify(password, hash string) error
}

// --- bcrypt ---

// BcryptHasher implements Hasher using bcrypt.
type BcryptHasher struct {
	Cost int
}

// NewBcryptHasher creates a BcryptHasher with the given cost.
// If cost is 0, bcrypt.DefaultCost is used.
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{Cost: cost}
}

// Hash returns a bcrypt hash of the password.
func (h *BcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.Cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash: %w", err)
	}
	return string(bytes), nil
}

// Verify checks whether the password matches the bcrypt hash.
func (h *BcryptHasher) Verify(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return errors.New("password does not match")
	}
	return nil
}

// --- argon2id ---

// Argon2idHasher implements Hasher using argon2id.
type Argon2idHasher struct {
	Time    uint32
	Memory  uint32 // in KiB
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// NewArgon2idHasher creates an Argon2idHasher with sensible defaults.
func NewArgon2idHasher() *Argon2idHasher {
	return &Argon2idHasher{
		Time:    1,
		Memory:  64 * 1024, // 64 MiB
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
}

// Hash returns an argon2id hash of the password in the standard encoded format:
// $argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>
func (h *Argon2idHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.Memory, h.Time, h.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)

	return encoded, nil
}

// Verify checks whether the password matches the argon2id hash.
func (h *Argon2idHasher) Verify(password, hash string) error {
	parts := strings.Split(hash, "$")
	// Expected format: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return errors.New("invalid argon2id hash format")
	}

	if parts[1] != "argon2id" {
		return fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	var memory uint32
	var time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return fmt.Errorf("parsing argon2id parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("decoding salt: %w", err)
	}

	expectedKey, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("decoding hash: %w", err)
	}

	expectedLen := len(expectedKey)
	if expectedLen < 0 || expectedLen > int(^uint32(0)) {
		return errors.New("invalid hash length")
	}
	keyLen := uint32(expectedLen) // #nosec G115 -- bounds checked above
	actualKey := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)

	if subtle.ConstantTimeCompare(actualKey, expectedKey) != 1 {
		return errors.New("password does not match")
	}

	return nil
}
