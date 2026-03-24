package oidc

import (
	"golang.org/x/crypto/bcrypt"
)

// checkPasswordHash compares a plaintext password against a bcrypt hash stored as bytes.
func checkPasswordHash(password string, hash []byte) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}
