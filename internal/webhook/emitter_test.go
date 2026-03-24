package webhook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/webhook"
)

func TestEmitSendsToEndpoint(t *testing.T) {
	var mu sync.Mutex
	var received []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := webhook.NewEmitter(config.WebhooksConfig{
		Endpoints: []config.WebhookEndpointConfig{
			{URL: srv.URL, Secret: "test-secret"},
		},
	})

	e.Emit(context.Background(), "user.login", map[string]string{"user_id": "u1"})
	time.Sleep(200 * time.Millisecond) // async delivery

	mu.Lock()
	defer mu.Unlock()
	if received == nil {
		t.Fatal("webhook not received")
	}

	var payload webhook.Payload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Event != "user.login" {
		t.Fatalf("want event user.login, got %s", payload.Event)
	}
}

func TestEmitHMACSignature(t *testing.T) {
	secret := "my-webhook-secret"
	var mu sync.Mutex
	var sig string
	var body []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		sig = r.Header.Get("X-Seki-Signature")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := webhook.NewEmitter(config.WebhooksConfig{
		Endpoints: []config.WebhookEndpointConfig{
			{URL: srv.URL, Secret: secret},
		},
	})

	e.Emit(context.Background(), "user.created", nil)
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Verify HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := fmt.Sprintf("sha256=%s", hex.EncodeToString(mac.Sum(nil)))

	if sig != expected {
		t.Fatalf("HMAC mismatch:\ngot  %s\nwant %s", sig, expected)
	}
}

func TestEmitEventFiltering(t *testing.T) {
	var mu sync.Mutex
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := webhook.NewEmitter(config.WebhooksConfig{
		Endpoints: []config.WebhookEndpointConfig{
			{URL: srv.URL, Events: []string{"user.login"}},
		},
	})

	e.Emit(context.Background(), "user.login", nil)   // should match
	e.Emit(context.Background(), "user.created", nil) // should NOT match
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if callCount != 1 {
		t.Fatalf("want 1 call (filtered), got %d", callCount)
	}
}

func TestEmitRetry(t *testing.T) {
	var mu sync.Mutex
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		a := attempts
		mu.Unlock()
		if a < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	e := webhook.NewEmitter(config.WebhooksConfig{
		Endpoints: []config.WebhookEndpointConfig{
			{URL: srv.URL},
		},
	})

	e.Emit(context.Background(), "test.event", nil)
	time.Sleep(5 * time.Second) // retries: 1s + 2s

	mu.Lock()
	defer mu.Unlock()
	if attempts < 3 {
		t.Fatalf("want at least 3 attempts (with retries), got %d", attempts)
	}
}
