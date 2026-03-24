package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	// Capture stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runVersion()

	w.Close()
	os.Stdout = old

	buf := make([]byte, 256)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "seki-cli v") {
		t.Errorf("expected version output, got: %s", output)
	}
	if !strings.Contains(output, version) {
		t.Errorf("expected version %s in output, got: %s", version, output)
	}
}

func TestKeygenCreatesValidPEM(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")

	runKeygen([]string{"--output", keyPath})

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found in key file")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("expected PEM type PRIVATE KEY, got %s", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing PKCS8 key: %v", err)
	}

	if _, ok := key.(ed25519.PrivateKey); !ok {
		t.Errorf("expected ed25519.PrivateKey, got %T", key)
	}

	// Check file permissions (owner read/write only).
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}

func TestUserListWithMockServer(t *testing.T) {
	users := []map[string]interface{}{
		{"id": "u1", "email": "alice@example.com", "display_name": "Alice", "disabled": false, "email_verified": false, "metadata": nil, "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"},
		{"id": "u2", "email": "bob@example.com", "display_name": "Bob", "disabled": false, "email_verified": false, "metadata": nil, "created_at": "2025-01-02T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"users": users,
		})
	}))
	defer srv.Close()

	// Capture stdout for table output.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runUser([]string{"list"}, srv.URL, "test-key", false)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "alice@example.com") {
		t.Errorf("expected alice@example.com in output, got: %s", output)
	}
	if !strings.Contains(output, "bob@example.com") {
		t.Errorf("expected bob@example.com in output, got: %s", output)
	}
}

func TestUserListJSONOutput(t *testing.T) {
	users := []map[string]interface{}{
		{"id": "u1", "email": "alice@example.com", "display_name": "Alice", "disabled": false, "email_verified": false, "metadata": nil, "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"users": users,
		})
	}))
	defer srv.Close()

	// Capture stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runUser([]string{"list"}, srv.URL, "test-key", true)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Verify it's valid JSON.
	var parsed []interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Errorf("expected valid JSON, got parse error: %v\noutput: %s", err, output)
	}

	if len(parsed) != 1 {
		t.Errorf("expected 1 user in JSON output, got %d", len(parsed))
	}
}

func TestRunNoArgs(t *testing.T) {
	// Redirect stderr to avoid noise.
	oldErr := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w

	code := run(nil)

	w.Close()
	os.Stderr = oldErr

	if code != 1 {
		t.Errorf("expected exit code 1 for no args, got %d", code)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	oldErr := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w

	code := run([]string{"nonexistent"})

	w.Close()
	os.Stderr = oldErr

	if code != 1 {
		t.Errorf("expected exit code 1 for unknown command, got %d", code)
	}
}

func TestGlobalFlagsAPIURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the Authorization header is set.
		auth := r.Header.Get("Authorization")
		if auth != "Bearer my-secret" {
			t.Errorf("expected Bearer my-secret, got %s", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"users": []interface{}{},
		})
	}))
	defer srv.Close()

	// Capture stdout.
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	code := run([]string{"--api-url", srv.URL, "--api-key", "my-secret", "user", "list"})

	w.Close()
	os.Stdout = old

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestEnvDefault(t *testing.T) {
	key := fmt.Sprintf("SEKI_TEST_%d", os.Getpid())

	// Unset: should return fallback.
	if v := envDefault(key, "fallback"); v != "fallback" {
		t.Errorf("expected fallback, got %s", v)
	}

	// Set: should return env value.
	os.Setenv(key, "from-env")
	defer os.Unsetenv(key)
	if v := envDefault(key, "fallback"); v != "from-env" {
		t.Errorf("expected from-env, got %s", v)
	}
}
