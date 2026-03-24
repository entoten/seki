package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Monet/seki/pkg/client"
)

// -----------------------------------------------------------------------
// Fake in-memory admin API for integration-style tests
// -----------------------------------------------------------------------

type fakeServer struct {
	mu      sync.Mutex
	users   map[string]client.User
	orgs    map[string]client.Organization
	members map[string][]client.OrgMember // orgSlug -> members
	roles   map[string][]client.Role      // orgSlug -> roles
	clients map[string]client.OAuthClient
	audit   []client.AuditEntry
	apiKey  string
}

func newFakeServer(apiKey string) *fakeServer {
	return &fakeServer{
		users:   make(map[string]client.User),
		orgs:    make(map[string]client.Organization),
		members: make(map[string][]client.OrgMember),
		roles:   make(map[string][]client.Role),
		clients: make(map[string]client.OAuthClient),
		apiKey:  apiKey,
	}
}

func (s *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Auth check
	if s.apiKey != "" {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+s.apiKey {
			s.writeProblem(w, http.StatusUnauthorized, "invalid API key")
			return
		}
	}

	path := r.URL.Path
	method := r.Method

	// Route to handlers
	switch {
	// Users
	case method == "POST" && path == "/api/v1/users":
		s.handleCreateUser(w, r)
	case method == "GET" && path == "/api/v1/users":
		s.handleListUsers(w, r)
	case method == "GET" && strings.HasPrefix(path, "/api/v1/users/"):
		s.handleGetUser(w, r)
	case method == "PATCH" && strings.HasPrefix(path, "/api/v1/users/"):
		s.handleUpdateUser(w, r)
	case method == "DELETE" && strings.HasPrefix(path, "/api/v1/users/"):
		s.handleDeleteUser(w, r)

	// Orgs
	case method == "POST" && path == "/api/v1/orgs":
		s.handleCreateOrg(w, r)
	case method == "GET" && path == "/api/v1/orgs":
		s.handleListOrgs(w, r)
	case method == "GET" && strings.Count(path, "/") == 4 && strings.HasPrefix(path, "/api/v1/orgs/"):
		s.handleGetOrg(w, r)
	case method == "PATCH" && strings.Count(path, "/") == 4 && strings.HasPrefix(path, "/api/v1/orgs/"):
		s.handleUpdateOrg(w, r)
	case method == "DELETE" && strings.Count(path, "/") == 4 && strings.HasPrefix(path, "/api/v1/orgs/"):
		s.handleDeleteOrg(w, r)

	// Members
	case method == "POST" && strings.HasSuffix(path, "/members"):
		s.handleAddMember(w, r)
	case method == "GET" && strings.HasSuffix(path, "/members"):
		s.handleListMembers(w, r)
	case method == "DELETE" && strings.Contains(path, "/members/"):
		s.handleRemoveMember(w, r)
	case method == "PATCH" && strings.Contains(path, "/members/"):
		s.handleUpdateMemberRole(w, r)

	// Roles
	case method == "POST" && strings.HasSuffix(path, "/roles"):
		s.handleCreateRole(w, r)
	case method == "GET" && strings.HasSuffix(path, "/roles"):
		s.handleListRoles(w, r)
	case method == "PATCH" && strings.Contains(path, "/roles/"):
		s.handleUpdateRole(w, r)
	case method == "DELETE" && strings.Contains(path, "/roles/"):
		s.handleDeleteRole(w, r)

	// Audit
	case method == "GET" && path == "/api/v1/audit-logs":
		s.handleListAuditLogs(w, r)

	// Clients
	case method == "POST" && path == "/api/v1/clients":
		s.handleCreateOAuthClient(w, r)
	case method == "GET" && path == "/api/v1/clients":
		s.handleListOAuthClients(w, r)
	case method == "GET" && strings.HasPrefix(path, "/api/v1/clients/"):
		s.handleGetOAuthClient(w, r)
	case method == "DELETE" && strings.HasPrefix(path, "/api/v1/clients/"):
		s.handleDeleteOAuthClient(w, r)

	default:
		s.writeProblem(w, http.StatusNotFound, "not found")
	}
}

func (s *fakeServer) writeProblem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
		"detail": detail,
	})
}

func (s *fakeServer) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// --- User handlers ---

func (s *fakeServer) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string          `json:"email"`
		DisplayName string          `json:"display_name"`
		Metadata    json.RawMessage `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.Email == req.Email {
			s.writeProblem(w, http.StatusConflict, "email already exists")
			return
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	id := generateID("usr")
	user := client.User{
		ID:          id,
		Email:       req.Email,
		DisplayName: req.DisplayName,
		Metadata:    req.Metadata,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if len(user.Metadata) == 0 {
		user.Metadata = json.RawMessage(`{}`)
	}
	s.users[id] = user
	s.writeJSON(w, http.StatusCreated, user)
}

func (s *fakeServer) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	s.mu.Lock()
	user, ok := s.users[id]
	s.mu.Unlock()
	if !ok {
		s.writeProblem(w, http.StatusNotFound, "user not found")
		return
	}
	s.writeJSON(w, http.StatusOK, user)
}

func (s *fakeServer) handleListUsers(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	var users []client.User
	for _, u := range s.users {
		users = append(users, u)
	}
	s.mu.Unlock()
	if users == nil {
		users = []client.User{}
	}

	// Simplified pagination: use limit, produce next_cursor if needed.
	cursor := r.URL.Query().Get("cursor")
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		var n int
		if _, err := json.Number(l).Int64(); err == nil {
			n = int(json.Number(l).String()[0] - '0') // simplified
		}
		_ = n
	}

	// Simple: skip past cursor if set.
	var result []client.User
	pastCursor := cursor == ""
	for _, u := range users {
		if !pastCursor {
			if u.ID == cursor {
				pastCursor = true
			}
			continue
		}
		result = append(result, u)
		if len(result) >= limit {
			break
		}
	}

	resp := struct {
		Users      []client.User `json:"users"`
		NextCursor string        `json:"next_cursor,omitempty"`
	}{
		Users: result,
	}
	if resp.Users == nil {
		resp.Users = []client.User{}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *fakeServer) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[id]
	if !ok {
		s.writeProblem(w, http.StatusNotFound, "user not found")
		return
	}

	var req struct {
		Email       *string          `json:"email"`
		DisplayName *string          `json:"display_name"`
		Disabled    *bool            `json:"disabled"`
		Metadata    *json.RawMessage `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, http.StatusBadRequest, "invalid body")
		return
	}

	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.DisplayName != nil {
		user.DisplayName = *req.DisplayName
	}
	if req.Disabled != nil {
		user.Disabled = *req.Disabled
	}
	if req.Metadata != nil {
		user.Metadata = *req.Metadata
	}
	user.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	s.users[id] = user
	s.writeJSON(w, http.StatusOK, user)
}

func (s *fakeServer) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		s.writeProblem(w, http.StatusNotFound, "user not found")
		return
	}
	delete(s.users, id)
	w.WriteHeader(http.StatusNoContent)
}

// --- Org handlers ---

func (s *fakeServer) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string          `json:"id"`
		Slug     string          `json:"slug"`
		Name     string          `json:"name"`
		Domains  []string        `json:"domains"`
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.orgs[req.Slug]; ok {
		s.writeProblem(w, http.StatusConflict, "organization already exists")
		return
	}
	if req.ID == "" {
		req.ID = "org_" + req.Slug
	}
	now := time.Now().UTC().Truncate(time.Second)
	org := client.Organization{
		ID:        req.ID,
		Slug:      req.Slug,
		Name:      req.Name,
		Domains:   req.Domains,
		Metadata:  req.Metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if org.Domains == nil {
		org.Domains = []string{}
	}
	if len(org.Metadata) == 0 {
		org.Metadata = json.RawMessage(`{}`)
	}
	s.orgs[req.Slug] = org
	s.writeJSON(w, http.StatusCreated, org)
}

func (s *fakeServer) handleGetOrg(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/api/v1/orgs/")
	s.mu.Lock()
	org, ok := s.orgs[slug]
	s.mu.Unlock()
	if !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	s.writeJSON(w, http.StatusOK, org)
}

func (s *fakeServer) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	var orgs []client.Organization
	for _, o := range s.orgs {
		orgs = append(orgs, o)
	}
	s.mu.Unlock()
	if orgs == nil {
		orgs = []client.Organization{}
	}
	resp := struct {
		Data       []client.Organization `json:"data"`
		NextCursor string                `json:"next_cursor,omitempty"`
	}{Data: orgs}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *fakeServer) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/api/v1/orgs/")
	s.mu.Lock()
	defer s.mu.Unlock()
	org, ok := s.orgs[slug]
	if !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	var req struct {
		Name     *string          `json:"name"`
		Slug     *string          `json:"slug"`
		Domains  []string         `json:"domains"`
		Metadata *json.RawMessage `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name != nil {
		org.Name = *req.Name
	}
	if req.Slug != nil {
		delete(s.orgs, slug)
		org.Slug = *req.Slug
	}
	if req.Domains != nil {
		org.Domains = req.Domains
	}
	if req.Metadata != nil {
		org.Metadata = *req.Metadata
	}
	org.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	s.orgs[org.Slug] = org
	s.writeJSON(w, http.StatusOK, org)
}

func (s *fakeServer) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/api/v1/orgs/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[slug]; !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	delete(s.orgs, slug)
	delete(s.members, slug)
	delete(s.roles, slug)
	w.WriteHeader(http.StatusNoContent)
}

// --- Member handlers ---

func (s *fakeServer) handleAddMember(w http.ResponseWriter, r *http.Request) {
	// path: /api/v1/orgs/{slug}/members
	parts := strings.Split(r.URL.Path, "/")
	slug := parts[4]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[slug]; !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	member := client.OrgMember{
		OrgID:    s.orgs[slug].ID,
		UserID:   req.UserID,
		Role:     req.Role,
		JoinedAt: time.Now().UTC().Truncate(time.Second),
	}
	s.members[slug] = append(s.members[slug], member)
	s.writeJSON(w, http.StatusCreated, member)
}

func (s *fakeServer) handleListMembers(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	slug := parts[4]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[slug]; !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	members := s.members[slug]
	if members == nil {
		members = []client.OrgMember{}
	}
	resp := struct {
		Data []client.OrgMember `json:"data"`
	}{Data: members}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *fakeServer) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	// path: /api/v1/orgs/{slug}/members/{user_id}
	parts := strings.Split(r.URL.Path, "/")
	slug := parts[4]
	userID := parts[6]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[slug]; !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	members := s.members[slug]
	found := false
	for i, m := range members {
		if m.UserID == userID {
			s.members[slug] = append(members[:i], members[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		s.writeProblem(w, http.StatusNotFound, "member not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *fakeServer) handleUpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	slug := parts[4]
	userID := parts[6]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[slug]; !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, http.StatusBadRequest, "invalid body")
		return
	}
	members := s.members[slug]
	for i, m := range members {
		if m.UserID == userID {
			members[i].Role = req.Role
			s.members[slug] = members
			s.writeJSON(w, http.StatusOK, members[i])
			return
		}
	}
	s.writeProblem(w, http.StatusNotFound, "member not found")
}

// --- Role handlers ---

func (s *fakeServer) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	slug := parts[4]
	s.mu.Lock()
	defer s.mu.Unlock()
	org, ok := s.orgs[slug]
	if !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	var req struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.ID == "" {
		req.ID = "role_" + slug + "_" + req.Name
	}
	role := client.Role{
		ID:          req.ID,
		OrgID:       org.ID,
		Name:        req.Name,
		Permissions: req.Permissions,
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}
	if role.Permissions == nil {
		role.Permissions = []string{}
	}
	s.roles[slug] = append(s.roles[slug], role)
	s.writeJSON(w, http.StatusCreated, role)
}

func (s *fakeServer) handleListRoles(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	slug := parts[4]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[slug]; !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	roles := s.roles[slug]
	if roles == nil {
		roles = []client.Role{}
	}
	resp := struct {
		Data []client.Role `json:"data"`
	}{Data: roles}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *fakeServer) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	slug := parts[4]
	roleName := parts[6]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[slug]; !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	var req struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, http.StatusBadRequest, "invalid body")
		return
	}
	roles := s.roles[slug]
	for i, rl := range roles {
		if rl.Name == roleName {
			roles[i].Permissions = req.Permissions
			s.roles[slug] = roles
			s.writeJSON(w, http.StatusOK, roles[i])
			return
		}
	}
	s.writeProblem(w, http.StatusNotFound, "role not found")
}

func (s *fakeServer) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	slug := parts[4]
	roleName := parts[6]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[slug]; !ok {
		s.writeProblem(w, http.StatusNotFound, "organization not found")
		return
	}
	roles := s.roles[slug]
	for i, rl := range roles {
		if rl.Name == roleName {
			s.roles[slug] = append(roles[:i], roles[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	s.writeProblem(w, http.StatusNotFound, "role not found")
}

// --- Audit handler ---

func (s *fakeServer) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	entries := make([]client.AuditEntry, len(s.audit))
	copy(entries, s.audit)
	s.mu.Unlock()

	q := r.URL.Query()
	if actorID := q.Get("actor_id"); actorID != "" {
		var filtered []client.AuditEntry
		for _, e := range entries {
			if e.ActorID == actorID {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}
	if action := q.Get("action"); action != "" {
		var filtered []client.AuditEntry
		for _, e := range entries {
			if e.Action == action {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if entries == nil {
		entries = []client.AuditEntry{}
	}
	resp := struct {
		Data       []client.AuditEntry `json:"data"`
		NextCursor string              `json:"next_cursor,omitempty"`
	}{Data: entries}
	s.writeJSON(w, http.StatusOK, resp)
}

// --- OAuth Client handlers ---

func (s *fakeServer) handleCreateOAuthClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
		GrantTypes   []string `json:"grant_types"`
		Scopes       []string `json:"scopes"`
		PKCERequired *bool    `json:"pkce_required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeProblem(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[req.ID]; ok {
		s.writeProblem(w, http.StatusConflict, "client already exists")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	pkce := true
	if req.PKCERequired != nil {
		pkce = *req.PKCERequired
	}
	oc := client.OAuthClient{
		ID:           req.ID,
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		Scopes:       req.Scopes,
		PKCERequired: pkce,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if oc.RedirectURIs == nil {
		oc.RedirectURIs = []string{}
	}
	if oc.GrantTypes == nil {
		oc.GrantTypes = []string{}
	}
	if oc.Scopes == nil {
		oc.Scopes = []string{}
	}
	s.clients[req.ID] = oc
	s.writeJSON(w, http.StatusCreated, oc)
}

func (s *fakeServer) handleGetOAuthClient(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	s.mu.Lock()
	oc, ok := s.clients[id]
	s.mu.Unlock()
	if !ok {
		s.writeProblem(w, http.StatusNotFound, "client not found")
		return
	}
	s.writeJSON(w, http.StatusOK, oc)
}

func (s *fakeServer) handleListOAuthClients(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	var list []client.OAuthClient
	for _, oc := range s.clients {
		list = append(list, oc)
	}
	s.mu.Unlock()
	if list == nil {
		list = []client.OAuthClient{}
	}
	resp := struct {
		Data []client.OAuthClient `json:"data"`
	}{Data: list}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *fakeServer) handleDeleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[id]; !ok {
		s.writeProblem(w, http.StatusNotFound, "client not found")
		return
	}
	delete(s.clients, id)
	w.WriteHeader(http.StatusNoContent)
}

// --- Helper ---

var idCounter int
var idMu sync.Mutex

func generateID(prefix string) string {
	idMu.Lock()
	defer idMu.Unlock()
	idCounter++
	return prefix + "_" + strings.Repeat("0", 5) + string(rune('0'+idCounter%10))
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

func setupTest(t *testing.T) (*client.Client, *fakeServer) {
	t.Helper()
	apiKey := "test-api-key-secret"
	fake := newFakeServer(apiKey)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	c := client.New(srv.URL, apiKey)
	return c, fake
}

func TestUserCRUD(t *testing.T) {
	c, _ := setupTest(t)
	ctx := context.Background()

	// Create
	user, err := c.CreateUser(ctx, client.CreateUserInput{
		Email:       "alice@example.com",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Errorf("email = %q, want %q", user.Email, "alice@example.com")
	}
	if user.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	// Get
	fetched, err := c.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if fetched.Email != user.Email {
		t.Errorf("GetUser email = %q, want %q", fetched.Email, user.Email)
	}

	// Update
	newName := "Alice Updated"
	updated, err := c.UpdateUser(ctx, user.ID, client.UpdateUserInput{
		DisplayName: &newName,
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.DisplayName != "Alice Updated" {
		t.Errorf("DisplayName = %q, want %q", updated.DisplayName, "Alice Updated")
	}

	// List
	list, err := c.ListUsers(ctx, client.ListOptions{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(list.Data) < 1 {
		t.Fatal("expected at least one user in list")
	}

	// Delete
	if err := c.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// Get after delete should 404
	_, err = c.GetUser(ctx, user.ID)
	if !client.IsNotFound(err) {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestAPIErrorParsing(t *testing.T) {
	c, _ := setupTest(t)
	ctx := context.Background()

	// 404
	_, err := c.GetUser(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	if !client.IsNotFound(err) {
		t.Errorf("expected IsNotFound, got %v", err)
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Status != 404 {
		t.Errorf("status = %d, want 404", apiErr.Status)
	}
	if apiErr.Detail != "user not found" {
		t.Errorf("detail = %q, want %q", apiErr.Detail, "user not found")
	}
	// Check Error() string
	errStr := apiErr.Error()
	if !strings.Contains(errStr, "404") {
		t.Errorf("error string %q should contain '404'", errStr)
	}
}

func TestConflictError(t *testing.T) {
	c, _ := setupTest(t)
	ctx := context.Background()

	_, err := c.CreateUser(ctx, client.CreateUserInput{
		Email:       "bob@example.com",
		DisplayName: "Bob",
	})
	if err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}

	// Same email again → 409
	_, err = c.CreateUser(ctx, client.CreateUserInput{
		Email:       "bob@example.com",
		DisplayName: "Bob 2",
	})
	if !client.IsConflict(err) {
		t.Errorf("expected IsConflict, got %v", err)
	}
}

func TestAPIKeyHeader(t *testing.T) {
	apiKey := "my-secret-key"
	fake := newFakeServer(apiKey)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	// Wrong key should fail
	badClient := client.New(srv.URL, "wrong-key")
	_, err := badClient.ListUsers(context.Background(), client.ListOptions{})
	if err == nil {
		t.Fatal("expected error with wrong API key")
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", apiErr.Status)
	}

	// Correct key should succeed
	goodClient := client.New(srv.URL, apiKey)
	_, err = goodClient.ListUsers(context.Background(), client.ListOptions{})
	if err != nil {
		t.Fatalf("expected success with correct key, got %v", err)
	}
}

func TestOrgCRUD(t *testing.T) {
	c, _ := setupTest(t)
	ctx := context.Background()

	// Create
	org, err := c.CreateOrg(ctx, client.CreateOrgInput{
		Slug: "acme",
		Name: "Acme Corp",
	})
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if org.Slug != "acme" {
		t.Errorf("slug = %q, want %q", org.Slug, "acme")
	}

	// Get
	fetched, err := c.GetOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("GetOrg: %v", err)
	}
	if fetched.Name != "Acme Corp" {
		t.Errorf("name = %q, want %q", fetched.Name, "Acme Corp")
	}

	// Update
	newName := "Acme Inc"
	updated, err := c.UpdateOrg(ctx, "acme", client.UpdateOrgInput{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("UpdateOrg: %v", err)
	}
	if updated.Name != "Acme Inc" {
		t.Errorf("name = %q, want %q", updated.Name, "Acme Inc")
	}

	// List
	list, err := c.ListOrgs(ctx, client.ListOptions{})
	if err != nil {
		t.Fatalf("ListOrgs: %v", err)
	}
	if len(list.Data) != 1 {
		t.Errorf("expected 1 org, got %d", len(list.Data))
	}

	// Delete
	if err := c.DeleteOrg(ctx, "acme"); err != nil {
		t.Fatalf("DeleteOrg: %v", err)
	}
	_, err = c.GetOrg(ctx, "acme")
	if !client.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestMemberOperations(t *testing.T) {
	c, _ := setupTest(t)
	ctx := context.Background()

	// Setup org
	_, err := c.CreateOrg(ctx, client.CreateOrgInput{Slug: "team", Name: "Team"})
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	// Add member
	member, err := c.AddMember(ctx, "team", client.AddMemberInput{
		UserID: "user-1",
		Role:   "admin",
	})
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if member.Role != "admin" {
		t.Errorf("role = %q, want %q", member.Role, "admin")
	}

	// List members
	members, err := c.ListMembers(ctx, "team")
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}

	// Update member role
	updated, err := c.UpdateMemberRole(ctx, "team", "user-1", client.UpdateMemberRoleInput{Role: "viewer"})
	if err != nil {
		t.Fatalf("UpdateMemberRole: %v", err)
	}
	if updated.Role != "viewer" {
		t.Errorf("role = %q, want %q", updated.Role, "viewer")
	}

	// Remove member
	if err := c.RemoveMember(ctx, "team", "user-1"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	members, err = c.ListMembers(ctx, "team")
	if err != nil {
		t.Fatalf("ListMembers after remove: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("expected 0 members, got %d", len(members))
	}
}

func TestRoleOperations(t *testing.T) {
	c, _ := setupTest(t)
	ctx := context.Background()

	// Setup org
	_, err := c.CreateOrg(ctx, client.CreateOrgInput{Slug: "corp", Name: "Corp"})
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	// Create role
	role, err := c.CreateRole(ctx, "corp", client.CreateRoleInput{
		Name:        "editor",
		Permissions: []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if role.Name != "editor" {
		t.Errorf("name = %q, want %q", role.Name, "editor")
	}

	// List roles
	roles, err := c.ListRoles(ctx, "corp")
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}

	// Update role
	updatedRole, err := c.UpdateRole(ctx, "corp", "editor", client.UpdateRoleInput{
		Permissions: []string{"read", "write", "delete"},
	})
	if err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	if len(updatedRole.Permissions) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(updatedRole.Permissions))
	}

	// Delete role
	if err := c.DeleteRole(ctx, "corp", "editor"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	roles, err = c.ListRoles(ctx, "corp")
	if err != nil {
		t.Fatalf("ListRoles after delete: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("expected 0 roles, got %d", len(roles))
	}
}

func TestAuditLogs(t *testing.T) {
	c, fake := setupTest(t)
	ctx := context.Background()

	// Seed some audit entries
	fake.mu.Lock()
	fake.audit = []client.AuditEntry{
		{ID: "a1", ActorID: "user-1", Action: "user.create", Resource: "user", ResourceID: "u1", CreatedAt: time.Now()},
		{ID: "a2", ActorID: "user-2", Action: "org.create", Resource: "org", ResourceID: "o1", CreatedAt: time.Now()},
		{ID: "a3", ActorID: "user-1", Action: "user.update", Resource: "user", ResourceID: "u1", CreatedAt: time.Now()},
	}
	fake.mu.Unlock()

	// List all
	result, err := c.ListAuditLogs(ctx, client.AuditListOptions{})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(result.Data) != 3 {
		t.Errorf("expected 3 entries, got %d", len(result.Data))
	}

	// Filter by actor
	result, err = c.ListAuditLogs(ctx, client.AuditListOptions{ActorID: "user-1"})
	if err != nil {
		t.Fatalf("ListAuditLogs with actor filter: %v", err)
	}
	if len(result.Data) != 2 {
		t.Errorf("expected 2 entries for user-1, got %d", len(result.Data))
	}

	// Filter by action
	result, err = c.ListAuditLogs(ctx, client.AuditListOptions{Action: "org.create"})
	if err != nil {
		t.Fatalf("ListAuditLogs with action filter: %v", err)
	}
	if len(result.Data) != 1 {
		t.Errorf("expected 1 entry for org.create, got %d", len(result.Data))
	}
}

func TestPagination(t *testing.T) {
	c, fake := setupTest(t)
	ctx := context.Background()

	// Create multiple users via the fake directly
	fake.mu.Lock()
	for i := 0; i < 5; i++ {
		id := generateID("usr")
		fake.users[id] = client.User{
			ID:        id,
			Email:     strings.Replace("user_N@example.com", "N", string(rune('0'+i)), 1),
			Metadata:  json.RawMessage(`{}`),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	}
	fake.mu.Unlock()

	// List with limit
	result, err := c.ListUsers(ctx, client.ListOptions{Limit: 3})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(result.Data) == 0 {
		t.Fatal("expected some users")
	}
}

func TestWithHTTPClient(t *testing.T) {
	apiKey := "test-key"
	fake := newFakeServer(apiKey)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	customHTTP := &http.Client{Timeout: 5 * time.Second}
	c := client.New(srv.URL, apiKey, client.WithHTTPClient(customHTTP))

	_, err := c.ListUsers(context.Background(), client.ListOptions{})
	if err != nil {
		t.Fatalf("ListUsers with custom HTTP client: %v", err)
	}
}

func TestOAuthClientCRUD(t *testing.T) {
	c, _ := setupTest(t)
	ctx := context.Background()

	pkce := true
	// Create
	oc, err := c.CreateClient(ctx, client.CreateClientInput{
		ID:           "my-app",
		Name:         "My Application",
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
		PKCERequired: &pkce,
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if oc.ID != "my-app" {
		t.Errorf("id = %q, want %q", oc.ID, "my-app")
	}
	if oc.Name != "My Application" {
		t.Errorf("name = %q, want %q", oc.Name, "My Application")
	}
	if !oc.PKCERequired {
		t.Error("expected PKCERequired to be true")
	}

	// Get
	fetched, err := c.GetClient(ctx, "my-app")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if fetched.Name != "My Application" {
		t.Errorf("name = %q, want %q", fetched.Name, "My Application")
	}

	// List
	list, err := c.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 client, got %d", len(list))
	}

	// Delete
	if err := c.DeleteClient(ctx, "my-app"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}

	// Get after delete should 404
	_, err = c.GetClient(ctx, "my-app")
	if !client.IsNotFound(err) {
		t.Errorf("expected not found error, got %v", err)
	}

	// List should be empty
	list, err = c.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients after delete: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 clients, got %d", len(list))
	}
}

func TestOAuthClientConflict(t *testing.T) {
	c, _ := setupTest(t)
	ctx := context.Background()

	_, err := c.CreateClient(ctx, client.CreateClientInput{
		ID:   "dup-client",
		Name: "Client 1",
	})
	if err != nil {
		t.Fatalf("first CreateClient: %v", err)
	}

	_, err = c.CreateClient(ctx, client.CreateClientInput{
		ID:   "dup-client",
		Name: "Client 2",
	})
	if !client.IsConflict(err) {
		t.Errorf("expected IsConflict, got %v", err)
	}
}
