package validate

import (
	"strings"
	"testing"
)

func TestEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid", "alice@example.com", false},
		{"empty", "", true},
		{"too long", "a@" + strings.Repeat("b", MaxEmailLen) + ".com", true},
		{"invalid format", "not-an-email", true},
		{"missing domain", "alice@", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Email(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("Email(%q) error = %v, wantErr %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestDisplayName(t *testing.T) {
	if err := DisplayName("Alice"); err != nil {
		t.Errorf("valid display name: %v", err)
	}
	if err := DisplayName(""); err != nil {
		t.Errorf("empty display name should be allowed: %v", err)
	}
	long := strings.Repeat("a", MaxDisplayNameLen+1)
	if err := DisplayName(long); err == nil {
		t.Error("expected error for too-long display name")
	}
}

func TestSlug(t *testing.T) {
	tests := []struct {
		name    string
		slug    string
		wantErr bool
	}{
		{"valid", "my-org", false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", MaxSlugLen+1), true},
		{"uppercase", "MyOrg", true},
		{"special chars", "my_org!", true},
		{"single char", "a", true}, // min 2 chars
		{"two chars", "ab", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Slug(tt.slug)
			if (err != nil) != tt.wantErr {
				t.Errorf("Slug(%q) error = %v, wantErr %v", tt.slug, err, tt.wantErr)
			}
		})
	}
}

func TestName(t *testing.T) {
	if err := Name("Acme Corp"); err != nil {
		t.Errorf("valid name: %v", err)
	}
	if err := Name(""); err == nil {
		t.Error("expected error for empty name")
	}
	if err := Name(strings.Repeat("x", MaxNameLen+1)); err == nil {
		t.Error("expected error for too-long name")
	}
}

func TestUUID(t *testing.T) {
	if err := UUID("550e8400-e29b-41d4-a716-446655440000"); err != nil {
		t.Errorf("valid UUID: %v", err)
	}
	if err := UUID(""); err == nil {
		t.Error("expected error for empty UUID")
	}
	if err := UUID("not-a-uuid"); err == nil {
		t.Error("expected error for invalid UUID")
	}
}

func TestClientID(t *testing.T) {
	if err := ClientID("my-app_v1.0"); err != nil {
		t.Errorf("valid client ID: %v", err)
	}
	if err := ClientID(""); err == nil {
		t.Error("expected error for empty client ID")
	}
	if err := ClientID("has spaces"); err == nil {
		t.Error("expected error for client ID with spaces")
	}
	if err := ClientID(strings.Repeat("a", 129)); err == nil {
		t.Error("expected error for too-long client ID")
	}
}

func TestPassword(t *testing.T) {
	if err := Password("securepass"); err != nil {
		t.Errorf("valid password: %v", err)
	}
	if err := Password(""); err == nil {
		t.Error("expected error for empty password")
	}
	if err := Password("short"); err == nil {
		t.Error("expected error for short password")
	}
	if err := Password(strings.Repeat("a", MaxPasswordLen+1)); err == nil {
		t.Error("expected error for too-long password")
	}
}

func TestRedirectURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"valid https", "https://app.example.com/callback", false},
		{"valid http", "http://localhost/callback", false},
		{"empty", "", true},
		{"too long", "https://example.com/" + strings.Repeat("a", MaxURLLen), true},
		{"javascript scheme", "javascript:alert(1)", true},
		{"data scheme", "data:text/html,<h1>hi</h1>", true},
		{"vbscript scheme", "vbscript:something", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RedirectURI(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("RedirectURI(%q) error = %v, wantErr %v", tt.uri, err, tt.wantErr)
			}
		})
	}
}

func TestRedirectURIs(t *testing.T) {
	if err := RedirectURIs([]string{"https://a.com/cb", "https://b.com/cb"}); err != nil {
		t.Errorf("valid URIs: %v", err)
	}
	if err := RedirectURIs([]string{"https://a.com/cb", "javascript:x"}); err == nil {
		t.Error("expected error for invalid URI in list")
	}
	if err := RedirectURIs(nil); err != nil {
		t.Errorf("nil list: %v", err)
	}
}

func TestURL(t *testing.T) {
	if err := URL("https://webhook.example.com/handler"); err != nil {
		t.Errorf("valid URL: %v", err)
	}
	if err := URL(""); err == nil {
		t.Error("expected error for empty URL")
	}
	if err := URL("ftp://files.example.com"); err == nil {
		t.Error("expected error for non-http scheme")
	}
	if err := URL("https://example.com/" + strings.Repeat("a", MaxURLLen)); err == nil {
		t.Error("expected error for too-long URL")
	}
}

func TestMetadata(t *testing.T) {
	if err := Metadata([]byte(`{"key":"val"}`)); err != nil {
		t.Errorf("valid metadata: %v", err)
	}
	if err := Metadata(nil); err != nil {
		t.Errorf("nil metadata: %v", err)
	}
	if err := Metadata(make([]byte, MaxMetadataBytes+1)); err == nil {
		t.Error("expected error for too-large metadata")
	}
}

func TestStringLength(t *testing.T) {
	if err := StringLength("field", "short", 100); err != nil {
		t.Errorf("valid string: %v", err)
	}
	if err := StringLength("field", strings.Repeat("a", 11), 10); err == nil {
		t.Error("expected error for too-long string")
	}
}
