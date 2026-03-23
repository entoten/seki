package crypto

import (
	"strings"
	"testing"
)

// --- bcrypt tests ---

func TestBcryptHasher_HashAndVerify(t *testing.T) {
	h := NewBcryptHasher(0)

	hash, err := h.Hash("mysecretpassword")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	if err := h.Verify("mysecretpassword", hash); err != nil {
		t.Fatalf("verify error: %v", err)
	}
}

func TestBcryptHasher_WrongPassword(t *testing.T) {
	h := NewBcryptHasher(0)

	hash, err := h.Hash("correct-password")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	if err := h.Verify("wrong-password", hash); err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestBcryptHasher_DifferentHashes(t *testing.T) {
	h := NewBcryptHasher(0)

	h1, err := h.Hash("password")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	h2, err := h.Hash("password")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	if h1 == h2 {
		t.Error("expected different hashes for the same password (due to salt)")
	}
}

func TestBcryptHasher_CustomCost(t *testing.T) {
	h := NewBcryptHasher(10)

	hash, err := h.Hash("password")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	if err := h.Verify("password", hash); err != nil {
		t.Fatalf("verify error: %v", err)
	}
}

// --- argon2id tests ---

func TestArgon2idHasher_HashAndVerify(t *testing.T) {
	h := NewArgon2idHasher()
	// Use lower memory for faster tests.
	h.Memory = 1024
	h.Time = 1

	hash, err := h.Hash("mysecretpassword")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("expected hash to start with $argon2id$, got %s", hash)
	}

	if err := h.Verify("mysecretpassword", hash); err != nil {
		t.Fatalf("verify error: %v", err)
	}
}

func TestArgon2idHasher_WrongPassword(t *testing.T) {
	h := NewArgon2idHasher()
	h.Memory = 1024
	h.Time = 1

	hash, err := h.Hash("correct-password")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	if err := h.Verify("wrong-password", hash); err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestArgon2idHasher_DifferentHashes(t *testing.T) {
	h := NewArgon2idHasher()
	h.Memory = 1024
	h.Time = 1

	h1, err := h.Hash("password")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	h2, err := h.Hash("password")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	if h1 == h2 {
		t.Error("expected different hashes for the same password (due to salt)")
	}
}

func TestArgon2idHasher_InvalidHash(t *testing.T) {
	h := NewArgon2idHasher()

	if err := h.Verify("password", "not-a-valid-hash"); err == nil {
		t.Error("expected error for invalid hash format")
	}
}

func TestArgon2idHasher_HashFormat(t *testing.T) {
	h := NewArgon2idHasher()
	h.Memory = 1024
	h.Time = 1

	hash, err := h.Hash("password")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("expected 6 parts in hash, got %d: %s", len(parts), hash)
	}

	if parts[1] != "argon2id" {
		t.Errorf("expected argon2id, got %s", parts[1])
	}

	if parts[2] != "v=19" {
		t.Errorf("expected v=19, got %s", parts[2])
	}
}

// Verify both hashers satisfy the Hasher interface at compile time.
var (
	_ Hasher = (*BcryptHasher)(nil)
	_ Hasher = (*Argon2idHasher)(nil)
)
