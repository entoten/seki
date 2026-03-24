// Package validate provides shared input validation helpers for the seki
// authentication server. Every user-facing API endpoint should funnel input
// through these functions before processing.
package validate

import (
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Limits defines maximum lengths for common input fields.
const (
	MaxEmailLen       = 254  // RFC 5321
	MaxDisplayNameLen = 256
	MaxSlugLen        = 64
	MaxNameLen        = 256
	MaxURLLen         = 2048
	MaxMetadataBytes  = 8192  // 8 KiB
	MaxJSONBodyBytes  = 65536 // 64 KiB – enforced via http.MaxBytesReader
	MaxPasswordLen    = 128   // avoid bcrypt/argon2 DoS with huge passwords
	MinPasswordLen    = 8
)

// uuidPattern matches a standard UUID v4 format.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// slugPattern matches lowercase alphanumeric slugs with hyphens.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,62}[a-z0-9]$`)

// clientIDPattern matches safe client identifiers.
var clientIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{1,128}$`)

// Email validates an email address format and length.
func Email(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}
	if len(email) > MaxEmailLen {
		return fmt.Errorf("email exceeds maximum length of %d characters", MaxEmailLen)
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// DisplayName validates a display name string.
func DisplayName(name string) error {
	if utf8.RuneCountInString(name) > MaxDisplayNameLen {
		return fmt.Errorf("display name exceeds maximum length of %d characters", MaxDisplayNameLen)
	}
	return nil
}

// Slug validates an organization or resource slug.
func Slug(slug string) error {
	if slug == "" {
		return fmt.Errorf("slug is required")
	}
	if len(slug) > MaxSlugLen {
		return fmt.Errorf("slug exceeds maximum length of %d characters", MaxSlugLen)
	}
	if !slugPattern.MatchString(slug) {
		return fmt.Errorf("slug must be lowercase alphanumeric with hyphens, 2-%d characters", MaxSlugLen)
	}
	return nil
}

// Name validates a generic name field (org name, client name, role name, etc).
func Name(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if utf8.RuneCountInString(name) > MaxNameLen {
		return fmt.Errorf("name exceeds maximum length of %d characters", MaxNameLen)
	}
	return nil
}

// UUID validates a UUID string format.
func UUID(id string) error {
	if id == "" {
		return fmt.Errorf("id is required")
	}
	if !uuidPattern.MatchString(id) {
		return fmt.Errorf("invalid UUID format")
	}
	return nil
}

// ClientID validates a client identifier.
func ClientID(id string) error {
	if id == "" {
		return fmt.Errorf("client id is required")
	}
	if !clientIDPattern.MatchString(id) {
		return fmt.Errorf("client id must be 1-128 alphanumeric characters, hyphens, underscores, or dots")
	}
	return nil
}

// Password validates a password meets minimum requirements.
func Password(password string) error {
	if password == "" {
		return fmt.Errorf("password is required")
	}
	if len(password) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(password) > MaxPasswordLen {
		return fmt.Errorf("password exceeds maximum length of %d characters", MaxPasswordLen)
	}
	return nil
}

// RedirectURI validates a redirect URI is safe (no javascript: or data: schemes).
func RedirectURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("redirect_uri is required")
	}
	if len(uri) > MaxURLLen {
		return fmt.Errorf("redirect_uri exceeds maximum length of %d characters", MaxURLLen)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri format")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "javascript" || scheme == "data" || scheme == "vbscript" {
		return fmt.Errorf("redirect_uri uses a forbidden scheme: %s", scheme)
	}
	return nil
}

// RedirectURIs validates a list of redirect URIs.
func RedirectURIs(uris []string) error {
	for i, uri := range uris {
		if err := RedirectURI(uri); err != nil {
			return fmt.Errorf("redirect_uris[%d]: %w", i, err)
		}
	}
	return nil
}

// URL validates a URL for safe schemes. Used for webhook URLs and similar.
func URL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("url is required")
	}
	if len(rawURL) > MaxURLLen {
		return fmt.Errorf("url exceeds maximum length of %d characters", MaxURLLen)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url format")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("url must use http or https scheme")
	}
	return nil
}

// Metadata validates that the metadata payload is within size limits.
func Metadata(data []byte) error {
	if len(data) > MaxMetadataBytes {
		return fmt.Errorf("metadata exceeds maximum size of %d bytes", MaxMetadataBytes)
	}
	return nil
}

// StringLength validates a generic string field does not exceed max length.
func StringLength(field string, value string, maxLen int) error {
	if utf8.RuneCountInString(value) > maxLen {
		return fmt.Errorf("%s exceeds maximum length of %d characters", field, maxLen)
	}
	return nil
}
