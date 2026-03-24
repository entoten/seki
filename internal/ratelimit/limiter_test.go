package ratelimit

import (
	"testing"
	"time"

	"github.com/entoten/seki/internal/config"
)

func newTestLimiter(rpm, maxAttempts int, lockout time.Duration) *Limiter {
	l := &Limiter{
		requestsPerMin:   rpm,
		loginAttemptsMax: maxAttempts,
		lockoutDuration:  lockout,
		stop:             make(chan struct{}),
	}
	return l
}

func TestAllow_UnderLimit(t *testing.T) {
	l := newTestLimiter(5, 5, 15*time.Minute)
	defer l.Stop()

	for i := 0; i < 5; i++ {
		if !l.Allow("client-1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestAllow_OverLimit(t *testing.T) {
	l := newTestLimiter(3, 5, 15*time.Minute)
	defer l.Stop()

	for i := 0; i < 3; i++ {
		if !l.Allow("client-2") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	if l.Allow("client-2") {
		t.Fatal("request over limit should be blocked")
	}
}

func TestAllow_WindowSlides(t *testing.T) {
	l := newTestLimiter(2, 5, 15*time.Minute)
	defer l.Stop()

	// Fill the window.
	l.Allow("client-3")
	l.Allow("client-3")

	if l.Allow("client-3") {
		t.Fatal("should be blocked at limit")
	}

	// Manually expire entries by reaching into the window.
	val, ok := l.windows.Load("client-3")
	if !ok {
		t.Fatal("window not found")
	}
	w := val.(*window)
	w.mu.Lock()
	// Set entries to 2 minutes ago so they're outside the sliding window.
	past := time.Now().Add(-2 * time.Minute)
	for i := range w.entries {
		w.entries[i] = past
	}
	w.mu.Unlock()

	// Now the window should have slid and new requests should be allowed.
	if !l.Allow("client-3") {
		t.Fatal("should be allowed after window slides")
	}
}

func TestLoginFailureTracking(t *testing.T) {
	l := newTestLimiter(60, 3, 15*time.Minute)
	defer l.Stop()

	ip := "192.168.1.1"
	email := "user@example.com"

	// First two failures should not lock.
	if locked := l.RecordLoginFailure(ip, email); locked {
		t.Fatal("should not be locked after 1 failure")
	}
	if locked := l.RecordLoginFailure(ip, email); locked {
		t.Fatal("should not be locked after 2 failures")
	}

	if l.IsLocked(ip, email) {
		t.Fatal("should not be locked before max attempts")
	}
}

func TestLockoutAfterMaxAttempts(t *testing.T) {
	l := newTestLimiter(60, 3, 15*time.Minute)
	defer l.Stop()

	ip := "192.168.1.2"
	email := "locked@example.com"

	l.RecordLoginFailure(ip, email)
	l.RecordLoginFailure(ip, email)
	locked := l.RecordLoginFailure(ip, email)

	if !locked {
		t.Fatal("should be locked after max attempts")
	}

	if !l.IsLocked(ip, email) {
		t.Fatal("IsLocked should return true after lockout")
	}
}

func TestLockoutExpires(t *testing.T) {
	l := newTestLimiter(60, 2, 50*time.Millisecond)
	defer l.Stop()

	ip := "192.168.1.3"
	email := "expire@example.com"

	l.RecordLoginFailure(ip, email)
	locked := l.RecordLoginFailure(ip, email)
	if !locked {
		t.Fatal("should be locked after max attempts")
	}

	if !l.IsLocked(ip, email) {
		t.Fatal("should be locked immediately after lockout")
	}

	// Wait for lockout to expire.
	time.Sleep(60 * time.Millisecond)

	if l.IsLocked(ip, email) {
		t.Fatal("lockout should have expired")
	}
}

func TestLoginSuccessResetsCounter(t *testing.T) {
	l := newTestLimiter(60, 3, 15*time.Minute)
	defer l.Stop()

	ip := "192.168.1.4"
	email := "reset@example.com"

	l.RecordLoginFailure(ip, email)
	l.RecordLoginFailure(ip, email)

	// Success should reset.
	l.RecordLoginSuccess(ip, email)

	// Should be able to fail again without immediate lockout.
	if locked := l.RecordLoginFailure(ip, email); locked {
		t.Fatal("should not be locked after success reset and 1 new failure")
	}
	if locked := l.RecordLoginFailure(ip, email); locked {
		t.Fatal("should not be locked after success reset and 2 new failures")
	}
}

func TestCleanupRemovesExpiredEntries(t *testing.T) {
	l := newTestLimiter(60, 2, 50*time.Millisecond)
	defer l.Stop()

	// Add a rate limit window entry in the past.
	l.Allow("cleanup-key")
	val, _ := l.windows.Load("cleanup-key")
	w := val.(*window)
	w.mu.Lock()
	w.entries[0] = time.Now().Add(-2 * time.Minute)
	w.mu.Unlock()

	// Add a login attempt that's expired.
	l.RecordLoginFailure("10.0.0.1", "cleanup@example.com")
	locked := l.RecordLoginFailure("10.0.0.1", "cleanup@example.com")
	if !locked {
		t.Fatal("should be locked")
	}

	// Wait for lockout to expire.
	time.Sleep(60 * time.Millisecond)

	// Run cleanup.
	l.cleanupOnce()

	// Window entry should be gone.
	if _, ok := l.windows.Load("cleanup-key"); ok {
		t.Fatal("expired window entry should be cleaned up")
	}

	// Login attempt entry should be gone.
	if _, ok := l.loginAttempts.Load(loginKey("10.0.0.1", "cleanup@example.com")); ok {
		t.Fatal("expired login attempt entry should be cleaned up")
	}
}

func TestNewLimiter_Defaults(t *testing.T) {
	l := NewLimiter(config.RateLimitConfig{})
	defer l.Stop()

	if l.requestsPerMin != 60 {
		t.Fatalf("expected default requestsPerMin 60, got %d", l.requestsPerMin)
	}
	if l.loginAttemptsMax != 5 {
		t.Fatalf("expected default loginAttemptsMax 5, got %d", l.loginAttemptsMax)
	}
	if l.lockoutDuration != 15*time.Minute {
		t.Fatalf("expected default lockoutDuration 15m, got %v", l.lockoutDuration)
	}
}

func TestNewLimiter_CustomConfig(t *testing.T) {
	l := NewLimiter(config.RateLimitConfig{
		Enabled:          true,
		RequestsPerMin:   100,
		LoginAttemptsMax: 10,
		LockoutDuration:  "30m",
	})
	defer l.Stop()

	if l.requestsPerMin != 100 {
		t.Fatalf("expected requestsPerMin 100, got %d", l.requestsPerMin)
	}
	if l.loginAttemptsMax != 10 {
		t.Fatalf("expected loginAttemptsMax 10, got %d", l.loginAttemptsMax)
	}
	if l.lockoutDuration != 30*time.Minute {
		t.Fatalf("expected lockoutDuration 30m, got %v", l.lockoutDuration)
	}
}
