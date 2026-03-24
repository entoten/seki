package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/entoten/seki/internal/config"
)

// Payload is the webhook delivery envelope.
type Payload struct {
	Event     string      `json:"event"`
	Timestamp string      `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Endpoint holds a single webhook target.
type Endpoint struct {
	URL    string
	Secret string
	Events []string // filter; empty = all events
}

// Emitter sends webhook events to configured endpoints.
type Emitter struct {
	endpoints []Endpoint
	client    *http.Client
}

// NewEmitter creates a webhook emitter from config.
func NewEmitter(cfg config.WebhooksConfig) *Emitter {
	var eps []Endpoint
	for _, e := range cfg.Endpoints {
		eps = append(eps, Endpoint{
			URL:    e.URL,
			Secret: e.Secret,
			Events: e.Events,
		})
	}
	return &Emitter{
		endpoints: eps,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Emit sends an event to all matching endpoints asynchronously.
func (e *Emitter) Emit(_ context.Context, event string, data interface{}) {
	if len(e.endpoints) == 0 {
		return
	}

	payload := Payload{
		Event:     event,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      data,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	for _, ep := range e.endpoints {
		if !ep.matchesEvent(event) {
			continue
		}
		go e.deliver(ep, body)
	}
}

// deliver sends the payload with retries (1s, 2s, 4s).
func (e *Emitter) deliver(ep Endpoint, body []byte) {
	backoff := time.Second
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		req, err := http.NewRequest(http.MethodPost, ep.URL, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		if ep.Secret != "" {
			sig := computeHMAC(body, ep.Secret)
			req.Header.Set("X-Seki-Signature", sig)
		}

		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return // success
		}
	}
}

func (ep Endpoint) matchesEvent(event string) bool {
	if len(ep.Events) == 0 {
		return true // no filter = all events
	}
	for _, e := range ep.Events {
		if e == event {
			return true
		}
	}
	return false
}

func computeHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return fmt.Sprintf("sha256=%s", hex.EncodeToString(mac.Sum(nil)))
}

// ComputeHMAC is exported for testing.
func ComputeHMAC(body []byte, secret string) string {
	return computeHMAC(body, secret)
}
