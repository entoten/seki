package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Monet/seki/internal/storage"
)

func TestBrandingDefaults(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create org
	body := `{"slug":"brand-default","name":"Brand Default Org","domains":["brand.com"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Get branding — should return defaults
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs/brand-default/branding", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get branding: expected 200, got %d", rec.Code)
	}

	var branding storage.OrgBranding
	_ = json.NewDecoder(rec.Body).Decode(&branding)
	// Default branding should have empty values (since we didn't set anything)
	if branding.LogoURL != "" {
		t.Fatalf("expected empty logo_url, got %q", branding.LogoURL)
	}
}

func TestBrandingUpdate(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create org
	body := `{"slug":"brand-update","name":"Brand Update Org"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Update branding
	body = `{"logo_url":"https://example.com/logo.png","primary_color":"#ff0000","background_color":"#000000","custom_css":"body{font-size:16px;}"}`
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/orgs/brand-update/branding", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update branding: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var updated storage.OrgBranding
	_ = json.NewDecoder(rec.Body).Decode(&updated)
	if updated.LogoURL != "https://example.com/logo.png" {
		t.Fatalf("logo_url mismatch: %q", updated.LogoURL)
	}
	if updated.PrimaryColor != "#ff0000" {
		t.Fatalf("primary_color mismatch: %q", updated.PrimaryColor)
	}
	if updated.BackgroundColor != "#000000" {
		t.Fatalf("background_color mismatch: %q", updated.BackgroundColor)
	}
	if updated.CustomCSS != "body{font-size:16px;}" {
		t.Fatalf("custom_css mismatch: %q", updated.CustomCSS)
	}

	// Verify via GET
	req = httptest.NewRequest(http.MethodGet, "/api/v1/orgs/brand-update/branding", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get branding: expected 200, got %d", rec.Code)
	}
	var fetched storage.OrgBranding
	_ = json.NewDecoder(rec.Body).Decode(&fetched)
	if fetched.PrimaryColor != "#ff0000" {
		t.Fatalf("expected #ff0000, got %q", fetched.PrimaryColor)
	}
}

func TestBrandingNotFoundOrg(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/nonexistent/branding", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}
