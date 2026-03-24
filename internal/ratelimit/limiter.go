package ratelimit

import (
	"sync"
	"time"

	"github.com/Monet/seki/internal/config"
)

// window tracks requests in a sliding window.
type window struct {
	mu      sync.Mutex
	entries []time.Time
}

// attempts tracks login failure attempts for brute-force protection.
type attempts struct {
	mu        sync.Mutex
	failures  int
	lockedAt  time.Time
	lastSeen  time.Time
}

// Limiter provides in-memory rate limiting and brute-force protection.
type Limiter struct {
	requestsPerMin   int
	loginAttemptsMax int
	lockoutDuration  time.Duration
	windows          sync.Map // key -> *window
	loginAttempts    sync.Map // "login:<ip>:<email>" -> *attempts
	stop             chan struct{}
}

// NewLimiter creates a new Limiter from the given configuration.
// It starts a background cleanup goroutine that runs every minute.
func NewLimiter(cfg config.RateLimitConfig) *Limiter {
	rpm := cfg.RequestsPerMin
	if rpm <= 0 {
		rpm = 60
	}

	maxAttempts := cfg.LoginAttemptsMax
	if maxAttempts <= 0 {
		maxAttempts = 5
	}

	lockout, err := time.ParseDuration(cfg.LockoutDuration)
	if err != nil || lockout <= 0 {
		lockout = 15 * time.Minute
	}

	l := &Limiter{
		requestsPerMin:   rpm,
		loginAttemptsMax: maxAttempts,
		lockoutDuration:  lockout,
		stop:             make(chan struct{}),
	}

	go l.cleanup()
	return l
}

// Allow checks whether a request identified by key is within the rate limit.
// It uses a sliding window of 1 minute.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	val, _ := l.windows.LoadOrStore(key, &window{})
	w := val.(*window)

	w.mu.Lock()
	defer w.mu.Unlock()

	// Remove entries outside the window.
	valid := w.entries[:0]
	for _, t := range w.entries {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	w.entries = valid

	if len(w.entries) >= l.requestsPerMin {
		return false
	}

	w.entries = append(w.entries, now)
	return true
}

// loginKey builds the map key for login attempt tracking.
func loginKey(ip, email string) string {
	return "login:" + ip + ":" + email
}

// RecordLoginFailure records a failed login attempt and returns true if the
// account is now locked out (i.e., max attempts reached).
func (l *Limiter) RecordLoginFailure(ip, email string) bool {
	key := loginKey(ip, email)
	now := time.Now()

	val, _ := l.loginAttempts.LoadOrStore(key, &attempts{})
	a := val.(*attempts)

	a.mu.Lock()
	defer a.mu.Unlock()

	// If currently locked and lockout has expired, reset.
	if !a.lockedAt.IsZero() && now.After(a.lockedAt.Add(l.lockoutDuration)) {
		a.failures = 0
		a.lockedAt = time.Time{}
	}

	a.failures++
	a.lastSeen = now

	if a.failures >= l.loginAttemptsMax {
		a.lockedAt = now
		return true
	}
	return false
}

// RecordLoginSuccess resets the failure count for the given IP/email pair.
func (l *Limiter) RecordLoginSuccess(ip, email string) {
	key := loginKey(ip, email)
	l.loginAttempts.Delete(key)
}

// IsLocked returns true if the given IP/email pair is currently locked out.
func (l *Limiter) IsLocked(ip, email string) bool {
	key := loginKey(ip, email)
	val, ok := l.loginAttempts.Load(key)
	if !ok {
		return false
	}

	a := val.(*attempts)
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.lockedAt.IsZero() {
		return false
	}

	if time.Now().After(a.lockedAt.Add(l.lockoutDuration)) {
		// Lockout expired; reset.
		a.failures = 0
		a.lockedAt = time.Time{}
		return false
	}

	return true
}

// cleanup periodically removes expired entries from both maps.
func (l *Limiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.cleanupOnce()
		case <-l.stop:
			return
		}
	}
}

// cleanupOnce removes stale entries from the windows and loginAttempts maps.
func (l *Limiter) cleanupOnce() {
	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	l.windows.Range(func(key, val any) bool {
		w := val.(*window)
		w.mu.Lock()
		valid := w.entries[:0]
		for _, t := range w.entries {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		w.entries = valid
		empty := len(w.entries) == 0
		w.mu.Unlock()

		if empty {
			l.windows.Delete(key)
		}
		return true
	})

	l.loginAttempts.Range(func(key, val any) bool {
		a := val.(*attempts)
		a.mu.Lock()
		expired := false
		if !a.lockedAt.IsZero() {
			// Remove if lockout has expired.
			expired = now.After(a.lockedAt.Add(l.lockoutDuration))
		} else {
			// Remove if no activity in the last lockout duration.
			expired = now.After(a.lastSeen.Add(l.lockoutDuration))
		}
		a.mu.Unlock()

		if expired {
			l.loginAttempts.Delete(key)
		}
		return true
	})
}

// Stop halts the background cleanup goroutine.
func (l *Limiter) Stop() {
	close(l.stop)
}
