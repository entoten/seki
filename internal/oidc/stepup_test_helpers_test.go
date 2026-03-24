package oidc_test

import (
	"time"

	"github.com/pquerna/otp/totp"
)

// generateTOTPCodeHelper generates a TOTP code for the given secret at the given time.
func generateTOTPCodeHelper(secret string, t time.Time) (string, error) {
	return totp.GenerateCode(secret, t)
}
