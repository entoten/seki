package validate

import (
	"strings"
	"testing"
)

// FuzzEmailValidation fuzzes the Email validation function.
// The main assertion is that Email never panics on any input.
func FuzzEmailValidation(f *testing.F) {
	// Valid emails.
	f.Add("user@example.com")
	f.Add("test.user+tag@subdomain.example.co.uk")
	f.Add("a@b.cc")

	// Invalid / edge cases.
	f.Add("")
	f.Add("not-an-email")
	f.Add("@missing-local.com")
	f.Add("missing-domain@")
	f.Add("user@.com")
	f.Add("user@com")
	f.Add(strings.Repeat("a", 300) + "@example.com")
	f.Add("user@" + strings.Repeat("x", 300) + ".com")
	f.Add("\x00user@example.com")
	f.Add("user name@example.com")
	f.Add("<script>@example.com")
	f.Add("user@example.com\x00")
	f.Add(`"quoted"@example.com`)

	f.Fuzz(func(t *testing.T, email string) {
		// Should never panic regardless of input.
		err := Email(email)

		// If it returns nil (valid), basic sanity checks.
		if err == nil {
			if !strings.Contains(email, "@") {
				t.Errorf("Email(%q) returned nil but input has no @", email)
			}
			if len(email) > MaxEmailLen {
				t.Errorf("Email(%q) returned nil but length %d exceeds max %d", email, len(email), MaxEmailLen)
			}
		}
	})
}

// FuzzRedirectURIValidation fuzzes the RedirectURI validation function.
// The main assertion is that RedirectURI never panics on any input.
func FuzzRedirectURIValidation(f *testing.F) {
	// Valid URIs.
	f.Add("https://example.com/callback")
	f.Add("http://localhost:8080/cb")
	f.Add("myapp://callback")
	f.Add("https://example.com/path?query=value#fragment")

	// Invalid / edge cases.
	f.Add("")
	f.Add("javascript:alert(1)")
	f.Add("data:text/html,<h1>hello</h1>")
	f.Add("vbscript:msgbox")
	f.Add(strings.Repeat("https://example.com/", 200))
	f.Add("://missing-scheme")
	f.Add("https://")
	f.Add("\x00\x01\x02")
	f.Add("https://example.com/" + strings.Repeat("a", 3000))
	f.Add("JAVASCRIPT:alert(1)")
	f.Add("  https://example.com/callback  ")
	f.Add("https://example.com/callback\x00evil")

	f.Fuzz(func(t *testing.T, uri string) {
		// Should never panic regardless of input.
		err := RedirectURI(uri)

		// If valid, verify forbidden schemes are not allowed.
		if err == nil {
			lower := strings.ToLower(uri)
			if strings.HasPrefix(lower, "javascript:") {
				t.Errorf("RedirectURI(%q) should reject javascript: scheme", uri)
			}
			if strings.HasPrefix(lower, "data:") {
				t.Errorf("RedirectURI(%q) should reject data: scheme", uri)
			}
			if strings.HasPrefix(lower, "vbscript:") {
				t.Errorf("RedirectURI(%q) should reject vbscript: scheme", uri)
			}
		}
	})
}

// FuzzSlugValidation fuzzes the Slug validation function.
// The main assertion is that Slug never panics on any input.
func FuzzSlugValidation(f *testing.F) {
	// Valid slugs.
	f.Add("my-org")
	f.Add("test123")
	f.Add("ab")
	f.Add("a0")
	f.Add("hello-world-123")

	// Invalid / edge cases.
	f.Add("")
	f.Add("a")
	f.Add("-starts-with-hyphen")
	f.Add("ends-with-hyphen-")
	f.Add("UPPERCASE")
	f.Add("has spaces")
	f.Add("has_underscore")
	f.Add(strings.Repeat("a", 100))
	f.Add("\x00")
	f.Add("valid" + "\x00" + "slug")
	f.Add("a-" + strings.Repeat("b", 62) + "-c")
	f.Add("<script>alert(1)</script>")

	f.Fuzz(func(t *testing.T, slug string) {
		// Should never panic regardless of input.
		err := Slug(slug)

		// If valid, verify constraints.
		if err == nil {
			if len(slug) > MaxSlugLen {
				t.Errorf("Slug(%q) returned nil but length %d exceeds max %d", slug, len(slug), MaxSlugLen)
			}
			if slug == "" {
				t.Errorf("Slug(%q) returned nil for empty string", slug)
			}
		}
	})
}
