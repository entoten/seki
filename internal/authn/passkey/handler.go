package passkey

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Monet/seki/internal/session"
	"github.com/Monet/seki/internal/storage"
)

// Handler serves the WebAuthn HTTP endpoints for passkey registration and login.
type Handler struct {
	svc      *Service
	store    storage.Storage
	sessions *session.Manager

	// challengeStore is a simple in-memory store for WebAuthn session data
	// (challenges). Entries expire after challengeTTL.
	mu             sync.Mutex
	challengeStore map[string]challengeEntry
}

type challengeEntry struct {
	data      string
	expiresAt time.Time
}

const challengeTTL = 5 * time.Minute

// NewHandler creates a new passkey HTTP handler.
func NewHandler(svc *Service, store storage.Storage, sessions *session.Manager) *Handler {
	h := &Handler{
		svc:            svc,
		store:          store,
		sessions:       sessions,
		challengeStore: make(map[string]challengeEntry),
	}
	// Start a background goroutine to clean up expired challenges.
	go h.cleanupLoop()
	return h
}

// RegisterRoutes registers the passkey routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /authn/passkey/register/begin", h.handleRegisterBegin)
	mux.HandleFunc("POST /authn/passkey/register/finish", h.handleRegisterFinish)
	mux.HandleFunc("POST /authn/passkey/login/begin", h.handleLoginBegin)
	mux.HandleFunc("POST /authn/passkey/login/finish", h.handleLoginFinish)
	mux.HandleFunc("POST /authn/passkey/login/discoverable/begin", h.handleDiscoverableLoginBegin)
	mux.HandleFunc("POST /authn/passkey/login/discoverable/finish", h.handleDiscoverableLoginFinish)

	// Credential lifecycle management.
	mux.HandleFunc("GET /authn/passkey/credentials", h.handleListCredentials)
	mux.HandleFunc("GET /authn/passkey/credentials/inactive", h.handleListInactiveCredentials)
	mux.HandleFunc("PATCH /authn/passkey/credentials/{id}", h.handleRenameCredential)
	mux.HandleFunc("DELETE /authn/passkey/credentials/{id}", h.handleDeleteCredential)
}

// --- Registration ---

func (h *Handler) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user, err := h.authenticatedUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "authentication required"})
		return
	}

	creation, sessionData, err := h.svc.BeginRegistration(r.Context(), user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("begin registration: %v", err)})
		return
	}

	// Store session data keyed by user ID + "register".
	key := "register:" + user.ID
	h.storeChallenge(key, sessionData)

	writeJSON(w, http.StatusOK, creation)
}

func (h *Handler) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, err := h.authenticatedUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "authentication required"})
		return
	}

	key := "register:" + user.ID
	sessionData, ok := h.loadChallenge(key)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no pending registration"})
		return
	}

	if err := h.svc.FinishRegistration(r.Context(), user, sessionData, r); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("finish registration: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Login (with username) ---

func (h *Handler) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "email is required"})
		return
	}

	user, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
		return
	}

	assertion, sessionData, err := h.svc.BeginLogin(r.Context(), user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("begin login: %v", err)})
		return
	}

	key := "login:" + user.ID
	h.storeChallenge(key, sessionData)

	writeJSON(w, http.StatusOK, loginBeginResponse{
		Assertion: assertion,
		UserID:    user.ID,
	})
}

func (h *Handler) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "user_id is required"})
		return
	}

	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
		return
	}

	key := "login:" + user.ID
	sessionData, ok := h.loadChallenge(key)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no pending login"})
		return
	}

	_, err = h.svc.FinishLogin(r.Context(), user, sessionData, r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: fmt.Sprintf("finish login: %v", err)})
		return
	}

	// Create a session for the user.
	sess, err := h.sessions.Create(r.Context(), user.ID, "", r.RemoteAddr, r.UserAgent())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "create session failed"})
		return
	}
	h.sessions.SetCookie(w, sess)

	writeJSON(w, http.StatusOK, map[string]string{
		"status":     "ok",
		"session_id": sess.ID,
	})
}

// --- Discoverable Login ---

func (h *Handler) handleDiscoverableLoginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, sessionData, err := h.svc.BeginDiscoverableLogin(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("begin discoverable login: %v", err)})
		return
	}

	// Use challenge as key since we don't know user yet.
	key := "discoverable:" + assertion.Response.Challenge.String()
	h.storeChallenge(key, sessionData)

	writeJSON(w, http.StatusOK, discoverableLoginBeginResponse{
		Assertion:    assertion,
		ChallengeKey: assertion.Response.Challenge.String(),
	})
}

func (h *Handler) handleDiscoverableLoginFinish(w http.ResponseWriter, r *http.Request) {
	challengeKey := r.URL.Query().Get("challenge_key")
	if challengeKey == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "challenge_key is required"})
		return
	}

	key := "discoverable:" + challengeKey
	sessionData, ok := h.loadChallenge(key)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no pending login"})
		return
	}

	user, _, err := h.svc.FinishDiscoverableLogin(r.Context(), sessionData, r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: fmt.Sprintf("finish discoverable login: %v", err)})
		return
	}

	sess, err := h.sessions.Create(r.Context(), user.ID, "", r.RemoteAddr, r.UserAgent())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "create session failed"})
		return
	}
	h.sessions.SetCookie(w, sess)

	writeJSON(w, http.StatusOK, map[string]string{
		"status":     "ok",
		"session_id": sess.ID,
		"user_id":    user.ID,
	})
}

// --- Credential lifecycle management ---

func (h *Handler) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	user, err := h.authenticatedUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "authentication required"})
		return
	}

	creds, err := h.svc.ListCredentials(r.Context(), user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("list credentials: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"credentials": creds})
}

func (h *Handler) handleRenameCredential(w http.ResponseWriter, r *http.Request) {
	user, err := h.authenticatedUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "authentication required"})
		return
	}

	credID := r.PathValue("id")
	if credID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "credential id is required"})
		return
	}

	// Verify the credential belongs to the authenticated user.
	cred, err := h.store.GetCredential(r.Context(), credID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "credential not found"})
		return
	}
	if cred.UserID != user.ID {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "credential does not belong to user"})
		return
	}

	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DisplayName == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "display_name is required"})
		return
	}

	if err := h.svc.RenameCredential(r.Context(), credID, req.DisplayName); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("rename credential: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	user, err := h.authenticatedUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "authentication required"})
		return
	}

	credID := r.PathValue("id")
	if credID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "credential id is required"})
		return
	}

	// Verify the credential belongs to the authenticated user.
	cred, err := h.store.GetCredential(r.Context(), credID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "credential not found"})
		return
	}
	if cred.UserID != user.ID {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "credential does not belong to user"})
		return
	}

	if err := h.svc.DeleteCredential(r.Context(), credID); err != nil {
		if strings.Contains(err.Error(), "cannot delete last") {
			writeJSON(w, http.StatusConflict, errorResponse{Error: "cannot delete last authentication credential"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("delete credential: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) handleListInactiveCredentials(w http.ResponseWriter, r *http.Request) {
	user, err := h.authenticatedUser(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "authentication required"})
		return
	}

	// Default threshold: 90 days.
	threshold := 90 * 24 * time.Hour
	if t := r.URL.Query().Get("threshold"); t != "" {
		parsed, err := time.ParseDuration(t)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid threshold duration"})
			return
		}
		threshold = parsed
	}

	creds, err := h.svc.GetInactiveCredentials(r.Context(), user.ID, threshold)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("list inactive credentials: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"credentials": creds})
}

// --- Challenge store helpers ---

func (h *Handler) storeChallenge(key, data string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.challengeStore[key] = challengeEntry{
		data:      data,
		expiresAt: time.Now().Add(challengeTTL),
	}
}

func (h *Handler) loadChallenge(key string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry, ok := h.challengeStore[key]
	if !ok {
		return "", false
	}
	delete(h.challengeStore, key)
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.data, true
}

func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.mu.Lock()
		now := time.Now()
		for k, v := range h.challengeStore {
			if now.After(v.expiresAt) {
				delete(h.challengeStore, k)
			}
		}
		h.mu.Unlock()
	}
}

// authenticatedUser extracts the authenticated user from the session cookie.
func (h *Handler) authenticatedUser(r *http.Request) (*storage.User, error) {
	sessionID, err := h.sessions.GetSessionID(r)
	if err != nil {
		return nil, fmt.Errorf("no session cookie")
	}
	sess, err := h.sessions.Get(r.Context(), sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %w", err)
	}
	user, err := h.store.GetUser(r.Context(), sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	return user, nil
}

// --- Response types ---

type errorResponse struct {
	Error string `json:"error"`
}

type loginBeginResponse struct {
	Assertion interface{} `json:"assertion"`
	UserID    string      `json:"user_id"`
}

type discoverableLoginBeginResponse struct {
	Assertion    interface{} `json:"assertion"`
	ChallengeKey string      `json:"challenge_key"`
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
