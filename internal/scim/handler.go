package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/entoten/seki/internal/admin"
	"github.com/entoten/seki/internal/storage"
)

// Handler serves the SCIM 2.0 provisioning API.
type Handler struct {
	store   storage.Storage
	apiKeys []string
	baseURL string
}

// NewHandler creates a new SCIM handler.
// baseURL is the externally-reachable base URL (e.g. "https://auth.example.com").
func NewHandler(store storage.Storage, baseURL string, apiKeys ...string) *Handler {
	return &Handler{
		store:   store,
		apiKeys: apiKeys,
		baseURL: strings.TrimRight(baseURL, "/"),
	}
}

// RegisterRoutes registers all SCIM 2.0 routes on the given mux.
// All routes are protected by Bearer token (API key) authentication.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	scimMux := http.NewServeMux()

	// Discovery endpoints.
	scimMux.HandleFunc("GET /scim/v2/ServiceProviderConfig", h.handleServiceProviderConfig)
	scimMux.HandleFunc("GET /scim/v2/Schemas", h.handleSchemas)
	scimMux.HandleFunc("GET /scim/v2/ResourceTypes", h.handleResourceTypes)

	// User endpoints.
	scimMux.HandleFunc("GET /scim/v2/Users", h.handleListUsers)
	scimMux.HandleFunc("GET /scim/v2/Users/{id}", h.handleGetUser)
	scimMux.HandleFunc("POST /scim/v2/Users", h.handleCreateUser)
	scimMux.HandleFunc("PATCH /scim/v2/Users/{id}", h.handlePatchUser)
	scimMux.HandleFunc("DELETE /scim/v2/Users/{id}", h.handleDeleteUser)

	// Group endpoints.
	scimMux.HandleFunc("GET /scim/v2/Groups", h.handleListGroups)
	scimMux.HandleFunc("GET /scim/v2/Groups/{id}", h.handleGetGroup)
	scimMux.HandleFunc("POST /scim/v2/Groups", h.handleCreateGroup)
	scimMux.HandleFunc("PATCH /scim/v2/Groups/{id}", h.handlePatchGroup)
	scimMux.HandleFunc("DELETE /scim/v2/Groups/{id}", h.handleDeleteGroup)

	authMiddleware := admin.RequireAPIKey(h.apiKeys)
	mux.Handle("/scim/v2/", authMiddleware(scimMux))
}

// ---------------------------------------------------------------------------
// Discovery endpoints
// ---------------------------------------------------------------------------

func (h *Handler) handleServiceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	config := map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://tools.ietf.org/html/rfc7644",
		"patch": map[string]any{
			"supported": true,
		},
		"bulk": map[string]any{
			"supported":      false,
			"maxOperations":  0,
			"maxPayloadSize": 0,
		},
		"filter": map[string]any{
			"supported":  true,
			"maxResults": 200,
		},
		"changePassword": map[string]any{
			"supported": false,
		},
		"sort": map[string]any{
			"supported": false,
		},
		"etag": map[string]any{
			"supported": false,
		},
		"authenticationSchemes": []map[string]any{
			{
				"type":             "oauthbearertoken",
				"name":             "OAuth Bearer Token",
				"description":      "Authentication scheme using the OAuth Bearer Token Standard",
				"specUri":          "https://tools.ietf.org/html/rfc6750",
				"documentationUri": "https://tools.ietf.org/html/rfc6750",
				"primary":          true,
			},
		},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     h.baseURL + "/scim/v2/ServiceProviderConfig",
		},
	}

	writeJSON(w, http.StatusOK, config)
}

func (h *Handler) handleSchemas(w http.ResponseWriter, _ *http.Request) {
	schemas := []map[string]any{
		{
			"id":          UserSchema,
			"name":        "User",
			"description": "User Account",
		},
		{
			"id":          GroupSchema,
			"name":        "Group",
			"description": "Group",
		},
	}

	resp := SCIMListResponse{
		Schemas:      []string{ListSchema},
		TotalResults: len(schemas),
		StartIndex:   1,
		ItemsPerPage: len(schemas),
		Resources:    schemas,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleResourceTypes(w http.ResponseWriter, _ *http.Request) {
	types := []map[string]any{
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "User",
			"name":        "User",
			"endpoint":    "/scim/v2/Users",
			"description": "User Account",
			"schema":      UserSchema,
			"meta": map[string]any{
				"resourceType": "ResourceType",
				"location":     h.baseURL + "/scim/v2/ResourceTypes/User",
			},
		},
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/scim/v2/Groups",
			"description": "Group",
			"schema":      GroupSchema,
			"meta": map[string]any{
				"resourceType": "ResourceType",
				"location":     h.baseURL + "/scim/v2/ResourceTypes/Group",
			},
		},
	}

	resp := SCIMListResponse{
		Schemas:      []string{ListSchema},
		TotalResults: len(types),
		StartIndex:   1,
		ItemsPerPage: len(types),
		Resources:    types,
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// User endpoints
// ---------------------------------------------------------------------------

func (h *Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	startIndex, count := parsePagination(q.Get("startIndex"), q.Get("count"))

	filterStr := q.Get("filter")
	filter := ParseFilter(filterStr)

	// Optimization: if filtering by userName eq, use direct email lookup.
	if filter != nil && strings.ToLower(filter.Attribute) == "username" && filter.Operator == "eq" {
		user, err := h.store.GetUserByEmail(r.Context(), filter.Value)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeJSON(w, http.StatusOK, SCIMListResponse{
					Schemas:      []string{ListSchema},
					TotalResults: 0,
					StartIndex:   1,
					ItemsPerPage: 0,
					Resources:    []any{},
				})
				return
			}
			writeSCIMError(w, http.StatusInternalServerError, "failed to search users")
			return
		}
		su := UserToSCIM(user, h.baseURL)
		writeJSON(w, http.StatusOK, SCIMListResponse{
			Schemas:      []string{ListSchema},
			TotalResults: 1,
			StartIndex:   1,
			ItemsPerPage: 1,
			Resources:    []*SCIMUser{su},
		})
		return
	}

	// Fetch all users with a reasonable limit for filtering.
	opts := storage.ListOptions{Limit: 200}
	users, _, err := h.store.ListUsers(r.Context(), opts)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	// Convert to SCIM and apply filter.
	scimUsers := make([]*SCIMUser, 0, len(users))
	for _, u := range users {
		su := UserToSCIM(u, h.baseURL)
		if filter != nil && !filter.MatchesUser(su) {
			continue
		}
		scimUsers = append(scimUsers, su)
	}

	totalResults := len(scimUsers)

	// Apply SCIM pagination (1-based startIndex).
	start := startIndex - 1 // convert to 0-based
	if start < 0 {
		start = 0
	}
	if start > len(scimUsers) {
		start = len(scimUsers)
	}
	end := start + count
	if end > len(scimUsers) {
		end = len(scimUsers)
	}
	page := scimUsers[start:end]
	if page == nil {
		page = []*SCIMUser{}
	}

	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListSchema},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(page),
		Resources:    page,
	})
}

func (h *Handler) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "user not found")
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	writeJSON(w, http.StatusOK, UserToSCIM(user, h.baseURL))
}

func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var su SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&su); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user := SCIMToUser(&su)

	if user.Email == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required")
		return
	}

	if err := h.store.CreateUser(r.Context(), user); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeSCIMError(w, http.StatusConflict, "user already exists")
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	result := UserToSCIM(user, h.baseURL)
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Location", result.Meta.Location)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

func (h *Handler) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	existing, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "user not found")
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	var patch SCIMPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	for _, op := range patch.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			h.applyReplaceOp(existing, op)
		case "add":
			h.applyReplaceOp(existing, op) // add and replace behave the same for single-valued attrs
		case "remove":
			h.applyRemoveOp(existing, op)
		}
	}

	existing.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	if err := h.store.UpdateUser(r.Context(), existing); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	// Re-fetch for updated timestamps.
	updated, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "failed to get updated user")
		return
	}

	writeJSON(w, http.StatusOK, UserToSCIM(updated, h.baseURL))
}

func (h *Handler) applyReplaceOp(user *storage.User, op SCIMPatchOp) {
	path := strings.ToLower(op.Path)

	switch {
	case path == "active":
		if b, ok := toBool(op.Value); ok {
			user.Disabled = !b
		}
	case path == "displayname":
		if s, ok := op.Value.(string); ok {
			user.DisplayName = s
		}
	case path == "username" || path == "emails[type eq \"work\"].value":
		if s, ok := op.Value.(string); ok {
			user.Email = s
		}
	case path == "name.givenname":
		// Update display name with given name.
		if s, ok := op.Value.(string); ok {
			parts := strings.SplitN(user.DisplayName, " ", 2)
			family := ""
			if len(parts) == 2 {
				family = parts[1]
			}
			user.DisplayName = strings.TrimSpace(s + " " + family)
		}
	case path == "name.familyname":
		if s, ok := op.Value.(string); ok {
			parts := strings.SplitN(user.DisplayName, " ", 2)
			given := ""
			if len(parts) >= 1 {
				given = parts[0]
			}
			user.DisplayName = strings.TrimSpace(given + " " + s)
		}
	case path == "":
		// No path means the value is a map of attributes to set.
		if m, ok := op.Value.(map[string]any); ok {
			for k, v := range m {
				h.applyReplaceOp(user, SCIMPatchOp{Op: "replace", Path: k, Value: v})
			}
		}
	}
}

func (h *Handler) applyRemoveOp(user *storage.User, op SCIMPatchOp) {
	path := strings.ToLower(op.Path)
	switch path {
	case "displayname":
		user.DisplayName = ""
	}
}

func (h *Handler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// SCIM DELETE deactivates (soft delete) rather than hard delete.
	existing, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "user not found")
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	existing.Disabled = true
	existing.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	if err := h.store.UpdateUser(r.Context(), existing); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "failed to deactivate user")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Group endpoints
// ---------------------------------------------------------------------------

func (h *Handler) handleListGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	startIndex, count := parsePagination(q.Get("startIndex"), q.Get("count"))

	opts := storage.ListOptions{Limit: 200}
	orgs, _, err := h.store.ListOrgs(r.Context(), opts)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}

	groups := make([]*SCIMGroup, 0, len(orgs))
	for _, org := range orgs {
		members, _ := h.store.ListMembers(r.Context(), org.ID)
		groups = append(groups, OrgToSCIMGroup(org, members, h.baseURL))
	}

	totalResults := len(groups)
	start := startIndex - 1
	if start < 0 {
		start = 0
	}
	if start > len(groups) {
		start = len(groups)
	}
	end := start + count
	if end > len(groups) {
		end = len(groups)
	}
	page := groups[start:end]
	if page == nil {
		page = []*SCIMGroup{}
	}

	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListSchema},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(page),
		Resources:    page,
	})
}

func (h *Handler) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	org, err := h.store.GetOrg(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "group not found")
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	members, _ := h.store.ListMembers(r.Context(), org.ID)
	writeJSON(w, http.StatusOK, OrgToSCIMGroup(org, members, h.baseURL))
}

func (h *Handler) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var sg SCIMGroup
	if err := json.NewDecoder(r.Body).Decode(&sg); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if sg.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required")
		return
	}

	now := time.Now().UTC().Truncate(time.Second)
	slug := strings.ToLower(strings.ReplaceAll(sg.DisplayName, " ", "-"))
	org := &storage.Organization{
		ID:        uuid.New().String(),
		Slug:      slug,
		Name:      sg.DisplayName,
		Domains:   []string{},
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreateOrg(r.Context(), org); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeSCIMError(w, http.StatusConflict, "group already exists")
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "failed to create group")
		return
	}

	// Add any initial members.
	for _, m := range sg.Members {
		member := &storage.OrgMember{
			OrgID:    org.ID,
			UserID:   m.Value,
			Role:     "member",
			JoinedAt: now,
		}
		_ = h.store.AddMember(r.Context(), member) // best-effort
	}

	members, _ := h.store.ListMembers(r.Context(), org.ID)
	result := OrgToSCIMGroup(org, members, h.baseURL)

	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Location", result.Meta.Location)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

func (h *Handler) handlePatchGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	org, err := h.store.GetOrg(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "group not found")
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	var patch SCIMPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	for _, op := range patch.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			if strings.ToLower(op.Path) == "displayname" {
				if s, ok := op.Value.(string); ok {
					org.Name = s
				}
			}
		case "add":
			if strings.ToLower(op.Path) == "members" {
				h.addGroupMembers(r, org.ID, op.Value)
			}
		case "remove":
			if strings.HasPrefix(strings.ToLower(op.Path), "members") {
				h.removeGroupMembers(r, org.ID, op.Path)
			}
		}
	}

	org.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	if err := h.store.UpdateOrg(r.Context(), org); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "failed to update group")
		return
	}

	members, _ := h.store.ListMembers(r.Context(), org.ID)
	writeJSON(w, http.StatusOK, OrgToSCIMGroup(org, members, h.baseURL))
}

func (h *Handler) addGroupMembers(r *http.Request, orgID string, value any) {
	members := toMemberList(value)
	now := time.Now().UTC()
	for _, m := range members {
		member := &storage.OrgMember{
			OrgID:    orgID,
			UserID:   m.Value,
			Role:     "member",
			JoinedAt: now,
		}
		_ = h.store.AddMember(r.Context(), member)
	}
}

func (h *Handler) removeGroupMembers(r *http.Request, orgID, path string) {
	// Path format: members[value eq "userId"]
	lower := strings.ToLower(path)
	if idx := strings.Index(lower, `value eq "`); idx >= 0 {
		rest := path[idx+len(`value eq "`):]
		if end := strings.Index(rest, `"`); end >= 0 {
			userID := rest[:end]
			_ = h.store.RemoveMember(r.Context(), orgID, userID)
		}
	}
}

func (h *Handler) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.DeleteOrg(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeSCIMError(w, http.StatusNotFound, "group not found")
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "failed to delete group")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parsePagination(startIndexStr, countStr string) (startIndex, count int) {
	startIndex = 1
	count = 100

	if v, err := strconv.Atoi(startIndexStr); err == nil && v > 0 {
		startIndex = v
	}
	if v, err := strconv.Atoi(countStr); err == nil && v >= 0 {
		count = v
	}
	if count > 200 {
		count = 200
	}
	return
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(SCIMError{
		Schemas: []string{ErrorSchema},
		Detail:  detail,
		Status:  fmt.Sprintf("%d", status),
	})
}

func toBool(v any) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		if b == "true" {
			return true, true
		}
		if b == "false" {
			return false, true
		}
	}
	return false, false
}

func toMemberList(v any) []SCIMMember {
	switch val := v.(type) {
	case []any:
		var members []SCIMMember
		for _, item := range val {
			if m, ok := item.(map[string]any); ok {
				member := SCIMMember{}
				if id, ok := m["value"].(string); ok {
					member.Value = id
				}
				if d, ok := m["display"].(string); ok {
					member.Display = d
				}
				members = append(members, member)
			}
		}
		return members
	case []SCIMMember:
		return val
	default:
		return nil
	}
}
