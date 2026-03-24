package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestID_GeneratesNew(t *testing.T) {
	handler := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := GetRequestID(r.Context())
		if id == "" {
			t.Error("expected request ID in context, got empty string")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	respID := rec.Header().Get(RequestIDHeader)
	if respID == "" {
		t.Error("expected X-Request-ID response header, got empty")
	}
	// UUID format: 8-4-4-4-12
	if len(respID) != 36 {
		t.Errorf("expected UUID-length request ID, got %q (len=%d)", respID, len(respID))
	}
}

func TestRequestID_Passthrough(t *testing.T) {
	const existingID = "my-proxy-id-12345"

	var contextID string
	handler := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, existingID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	respID := rec.Header().Get(RequestIDHeader)
	if respID != existingID {
		t.Errorf("expected passthrough ID %q, got %q", existingID, respID)
	}
	if contextID != existingID {
		t.Errorf("expected context ID %q, got %q", existingID, contextID)
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	handler := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ids := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		id := rec.Header().Get(RequestIDHeader)
		if _, exists := ids[id]; exists {
			t.Fatalf("duplicate request ID: %s", id)
		}
		ids[id] = struct{}{}
	}
}
