package social

import (
	"net/url"
	"testing"

	"github.com/Monet/seki/internal/config"
)

func TestGetAuthURL_Google(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"google": {
			ClientID:     "google-client-id",
			ClientSecret: "google-client-secret",
		},
	}

	svc := NewService(cfg, nil)

	authURL, err := svc.GetAuthURL("google", "test-state-123", "https://example.com/callback")
	if err != nil {
		t.Fatalf("GetAuthURL: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}

	if parsed.Scheme != "https" {
		t.Errorf("expected https scheme, got %s", parsed.Scheme)
	}

	if parsed.Host != "accounts.google.com" {
		t.Errorf("expected accounts.google.com host, got %s", parsed.Host)
	}

	params := parsed.Query()

	if got := params.Get("client_id"); got != "google-client-id" {
		t.Errorf("expected client_id=google-client-id, got %s", got)
	}

	if got := params.Get("redirect_uri"); got != "https://example.com/callback" {
		t.Errorf("expected redirect_uri=https://example.com/callback, got %s", got)
	}

	if got := params.Get("response_type"); got != "code" {
		t.Errorf("expected response_type=code, got %s", got)
	}

	if got := params.Get("state"); got != "test-state-123" {
		t.Errorf("expected state=test-state-123, got %s", got)
	}

	if got := params.Get("scope"); got != "openid email profile" {
		t.Errorf("expected scope=openid email profile, got %s", got)
	}
}

func TestGetAuthURL_GitHub(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"github": {
			ClientID:     "github-client-id",
			ClientSecret: "github-client-secret",
		},
	}

	svc := NewService(cfg, nil)

	authURL, err := svc.GetAuthURL("github", "state-abc", "https://example.com/cb")
	if err != nil {
		t.Fatalf("GetAuthURL: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}

	if parsed.Host != "github.com" {
		t.Errorf("expected github.com host, got %s", parsed.Host)
	}

	params := parsed.Query()

	if got := params.Get("client_id"); got != "github-client-id" {
		t.Errorf("expected client_id=github-client-id, got %s", got)
	}

	if got := params.Get("scope"); got != "user:email" {
		t.Errorf("expected scope=user:email, got %s", got)
	}
}

func TestNewService_Google(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"google": {
			ClientID:     "gid",
			ClientSecret: "gsecret",
		},
	}

	svc := NewService(cfg, nil)

	p, err := svc.GetProvider("google")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}

	if p.ClientID != "gid" {
		t.Errorf("expected ClientID=gid, got %s", p.ClientID)
	}
	if p.ClientSecret != "gsecret" {
		t.Errorf("expected ClientSecret=gsecret, got %s", p.ClientSecret)
	}
	if p.AuthURL != "https://accounts.google.com/o/oauth2/v2/auth" {
		t.Errorf("unexpected AuthURL: %s", p.AuthURL)
	}
	if p.TokenURL != "https://oauth2.googleapis.com/token" {
		t.Errorf("unexpected TokenURL: %s", p.TokenURL)
	}
	if p.UserInfoURL != "https://www.googleapis.com/oauth2/v3/userinfo" {
		t.Errorf("unexpected UserInfoURL: %s", p.UserInfoURL)
	}
}

func TestNewService_GitHub(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"github": {
			ClientID:     "ghid",
			ClientSecret: "ghsecret",
		},
	}

	svc := NewService(cfg, nil)

	p, err := svc.GetProvider("github")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}

	if p.ClientID != "ghid" {
		t.Errorf("expected ClientID=ghid, got %s", p.ClientID)
	}
	if p.AuthURL != "https://github.com/login/oauth/authorize" {
		t.Errorf("unexpected AuthURL: %s", p.AuthURL)
	}
	if p.TokenURL != "https://github.com/login/oauth/access_token" {
		t.Errorf("unexpected TokenURL: %s", p.TokenURL)
	}
	if p.UserInfoURL != "https://api.github.com/user" {
		t.Errorf("unexpected UserInfoURL: %s", p.UserInfoURL)
	}
}

func TestUnknownProvider(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"google": {
			ClientID:     "gid",
			ClientSecret: "gsecret",
		},
	}

	svc := NewService(cfg, nil)

	_, err := svc.GetAuthURL("twitter", "state", "https://example.com/cb")
	if err != ErrUnknownProvider {
		t.Fatalf("expected ErrUnknownProvider, got %v", err)
	}

	_, err = svc.GetProvider("twitter")
	if err != ErrUnknownProvider {
		t.Fatalf("expected ErrUnknownProvider, got %v", err)
	}
}
