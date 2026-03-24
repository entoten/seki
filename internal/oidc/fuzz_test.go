package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// FuzzTokenRequestParsing fuzzes the token endpoint with random form data.
// The main assertion is that the handler never panics on any input.
func FuzzTokenRequestParsing(f *testing.F) {
	// Seed corpus: valid and edge-case form bodies.
	f.Add("grant_type=authorization_code&code=abc123&redirect_uri=https://example.com/cb&client_id=test&client_secret=secret&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	f.Add("grant_type=client_credentials&client_id=test&client_secret=secret&scope=openid")
	f.Add("grant_type=refresh_token&refresh_token=abc123&client_id=test")
	f.Add("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=abc&client_id=test")
	f.Add("grant_type=invalid")
	f.Add("")
	f.Add("grant_type=authorization_code")
	f.Add("grant_type=authorization_code&code=&client_id=")
	f.Add(strings.Repeat("a", 10000))
	f.Add("grant_type=" + strings.Repeat("x", 1000))
	f.Add("key1=val1&key2=val2&key3=val3&key4=val4&key5=val5")
	f.Add("%00%01%02%03")

	f.Fuzz(func(t *testing.T, body string) {
		// Should never panic regardless of input.
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()
		// We only test form parsing and grant type dispatch logic, not the full
		// handler (which requires a Provider with storage). The key assertion is
		// that ParseForm + reading form values does not panic.
		_ = req.PostFormValue("grant_type")
		_ = req.PostFormValue("code")
		_ = req.PostFormValue("redirect_uri")
		_ = req.PostFormValue("client_id")
		_ = req.PostFormValue("client_secret")
		_ = req.PostFormValue("code_verifier")
		_ = req.PostFormValue("refresh_token")
		_ = req.PostFormValue("scope")
	})
}

// FuzzPKCEVerification fuzzes the PKCE code_verifier validation.
// The function should never panic regardless of input.
func FuzzPKCEVerification(f *testing.F) {
	// Valid PKCE pair.
	validVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	f.Add(validVerifier, validChallenge)
	f.Add("", "")
	f.Add("short", "short")
	f.Add(strings.Repeat("a", 128), strings.Repeat("b", 128))
	f.Add("abc123", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	f.Add(strings.Repeat("\x00", 64), strings.Repeat("\xff", 64))
	f.Add("valid-verifier-here", "")
	f.Add("", "valid-challenge-here")
	f.Add(url.QueryEscape("special+chars&more=stuff"), "challenge")

	f.Fuzz(func(t *testing.T, verifier, challenge string) {
		// Should never panic. We only check that it returns a bool.
		result := verifyPKCE(verifier, challenge)

		// If the challenge is actually the S256 of the verifier, it must be true.
		expected := sha256.Sum256([]byte(verifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(expected[:])
		if challenge == expectedChallenge && !result {
			t.Errorf("verifyPKCE returned false for valid pair: verifier=%q challenge=%q", verifier, challenge)
		}
	})
}
