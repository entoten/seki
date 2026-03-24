package social

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
)

// Well-known OAuth2 endpoints for supported providers.
// #nosec G101 -- false positive: these are public OAuth2 endpoint URLs, not credentials
var knownProviders = map[string]Provider{
	"google": {
		Name:        "google",
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserInfoURL: "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:      []string{"openid", "email", "profile"},
	},
	"github": {
		Name:        "github",
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user",
		Scopes:      []string{"user:email"},
	},
}

// Errors returned by the social service.
var (
	ErrUnknownProvider = errors.New("social: unknown provider")
	ErrExchangeFailed  = errors.New("social: token exchange failed")
	ErrUserInfoFailed  = errors.New("social: failed to fetch user info")
)

// Provider holds OAuth2 configuration for a social login provider.
type Provider struct {
	Name         string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
}

// SocialUser represents a user profile obtained from a social provider.
type SocialUser struct {
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	AvatarURL  string `json:"avatar_url"`
}

// Service provides social login functionality.
type Service struct {
	providers map[string]*Provider
	store     storage.Storage
	client    *http.Client
}

// NewService creates a new social login service from configuration.
func NewService(cfg map[string]config.SocialProvider, store storage.Storage) *Service {
	providers := make(map[string]*Provider)

	for name, sp := range cfg {
		known, ok := knownProviders[name]
		if !ok {
			continue
		}
		p := &Provider{
			Name:         known.Name,
			ClientID:     sp.ClientID,
			ClientSecret: sp.ClientSecret,
			AuthURL:      known.AuthURL,
			TokenURL:     known.TokenURL,
			UserInfoURL:  known.UserInfoURL,
			Scopes:       known.Scopes,
		}
		providers[name] = p
	}

	return &Service{
		providers: providers,
		store:     store,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// GetProvider returns the provider by name, or an error if not found.
func (s *Service) GetProvider(name string) (*Provider, error) {
	p, ok := s.providers[name]
	if !ok {
		return nil, ErrUnknownProvider
	}
	return p, nil
}

// GetAuthURL builds the OAuth2 authorization URL for the given provider.
func (s *Service) GetAuthURL(providerName string, state string, redirectURL string) (string, error) {
	p, err := s.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	params := url.Values{
		"client_id":     {p.ClientID},
		"redirect_uri":  {redirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(p.Scopes, " ")},
		"state":         {state},
	}

	return p.AuthURL + "?" + params.Encode(), nil
}

// Exchange exchanges an authorization code for an access token and fetches user info.
func (s *Service) Exchange(ctx context.Context, providerName string, code string, redirectURL string) (*SocialUser, error) {
	p, err := s.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Exchange code for token.
	tokenData, err := s.exchangeCode(ctx, p, code, redirectURL)
	if err != nil {
		return nil, err
	}

	accessToken, ok := tokenData["access_token"].(string)
	if !ok || accessToken == "" {
		return nil, ErrExchangeFailed
	}

	// Fetch user info.
	user, err := s.fetchUserInfo(ctx, p, accessToken)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// LinkAccount links a social identity to an existing user by storing a credential.
func (s *Service) LinkAccount(ctx context.Context, socialUser *SocialUser, existingUserID string) error {
	meta, err := json.Marshal(map[string]string{
		"provider":    socialUser.Provider,
		"provider_id": socialUser.ProviderID,
		"email":       socialUser.Email,
		"name":        socialUser.Name,
		"avatar_url":  socialUser.AvatarURL,
	})
	if err != nil {
		return fmt.Errorf("social: marshal metadata: %w", err)
	}

	now := time.Now().UTC()
	cred := &storage.Credential{
		ID:        generateID(),
		UserID:    existingUserID,
		Type:      "social:" + socialUser.Provider,
		Secret:    []byte(socialUser.ProviderID),
		Metadata:  meta,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.CreateCredential(ctx, cred); err != nil {
		return fmt.Errorf("social: create credential: %w", err)
	}
	return nil
}

// FindOrCreateUser finds a user by email or creates a new one.
// Returns the user and a boolean indicating whether the user was newly created.
func (s *Service) FindOrCreateUser(ctx context.Context, socialUser *SocialUser) (*storage.User, bool, error) {
	// Try to find existing user by email.
	user, err := s.store.GetUserByEmail(ctx, socialUser.Email)
	if err == nil {
		return user, false, nil
	}

	if !errors.Is(err, storage.ErrNotFound) {
		return nil, false, fmt.Errorf("social: lookup user: %w", err)
	}

	// Create new user.
	now := time.Now().UTC()
	user = &storage.User{
		ID:          generateID(),
		Email:       socialUser.Email,
		DisplayName: socialUser.Name,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.store.CreateUser(ctx, user); err != nil {
		return nil, false, fmt.Errorf("social: create user: %w", err)
	}

	return user, true, nil
}

// exchangeCode performs the OAuth2 token exchange.
func (s *Service) exchangeCode(ctx context.Context, p *Provider, code string, redirectURL string) (map[string]interface{}, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURL},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("social: create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("social: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("social: read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrExchangeFailed, resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("social: parse token response: %w", err)
	}

	return result, nil
}

// fetchUserInfo fetches the user's profile from the provider's userinfo endpoint.
func (s *Service) fetchUserInfo(ctx context.Context, p *Provider, accessToken string) (*SocialUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("social: create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("social: userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("social: read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrUserInfoFailed, resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("social: parse userinfo response: %w", err)
	}

	user := &SocialUser{
		Provider: p.Name,
	}

	// Parse provider-specific fields.
	switch p.Name {
	case "google":
		user.ProviderID = stringFromMap(data, "sub")
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")
		user.AvatarURL = stringFromMap(data, "picture")
	case "github":
		if id, ok := data["id"].(float64); ok {
			user.ProviderID = fmt.Sprintf("%.0f", id)
		}
		user.Email = stringFromMap(data, "email")
		user.Name = stringFromMap(data, "name")
		if user.Name == "" {
			user.Name = stringFromMap(data, "login")
		}
		user.AvatarURL = stringFromMap(data, "avatar_url")
	}

	return user, nil
}

// stringFromMap safely extracts a string value from a map.
func stringFromMap(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// generateID creates a unique ID.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
