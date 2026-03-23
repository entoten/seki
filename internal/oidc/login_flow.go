package oidc

import (
	"golang.org/x/crypto/bcrypt"
)

// checkPasswordHash compares a plaintext password against a bcrypt hash stored as bytes.
func checkPasswordHash(password string, hash []byte) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

// hashPassword hashes a password using bcrypt. Used in tests and setup.
func hashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}
