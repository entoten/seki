package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/validate"
)

// registerClientRoutesOn registers client-related admin API routes on the given mux.
func (h *Handler) registerClientRoutesOn(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/clients", h.handleCreateClient)
	mux.HandleFunc("GET /api/v1/clients", h.handleListClients)
	mux.HandleFunc("GET /api/v1/clients/{id}", h.handleGetClient)
	mux.HandleFunc("DELETE /api/v1/clients/{id}", h.handleDeleteClient)
}

// ---------------------------------------------------------------------------
// Client CRUD
// ---------------------------------------------------------------------------

type createClientRequest struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
	PKCERequired *bool    `json:"pkce_required"`
}

func (h *Handler) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body")
		return
	}
	if err := validate.ClientID(req.ID); err != nil {
		writeProblem(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, err.Error())
		return
	}
	if err := validate.Name(req.Name); err != nil {
		writeProblem(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, err.Error())
		return
	}
	if err := validate.RedirectURIs(req.RedirectURIs); err != nil {
		writeProblem(w, r, http.StatusBadRequest, ErrCodeInvalidRedirectURI, err.Error())
		return
	}

	now := time.Now().UTC()
	client := &storage.Client{
		ID:           req.ID,
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		Scopes:       req.Scopes,
		PKCERequired: true, // default
		Metadata:     json.RawMessage(`{}`),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if req.PKCERequired != nil {
		client.PKCERequired = *req.PKCERequired
	}
	if client.RedirectURIs == nil {
		client.RedirectURIs = []string{}
	}
	if client.GrantTypes == nil {
		client.GrantTypes = []string{}
	}
	if client.Scopes == nil {
		client.Scopes = []string{}
	}

	if err := h.store.CreateClient(r.Context(), client); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeProblem(w, r, http.StatusConflict, ErrCodeConflict, "client already exists")
			return
		}
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to create client")
		return
	}

	writeJSON(w, http.StatusCreated, client)
}

func (h *Handler) handleGetClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	client, err := h.store.GetClient(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, ErrCodeInvalidClient, "client not found")
			return
		}
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to get client")
		return
	}
	writeJSON(w, http.StatusOK, client)
}

type clientListResponse struct {
	Data []*storage.Client `json:"data"`
}

func (h *Handler) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.store.ListClients(r.Context())
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to list clients")
		return
	}
	if clients == nil {
		clients = []*storage.Client{}
	}
	writeJSON(w, http.StatusOK, clientListResponse{Data: clients})
}

func (h *Handler) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.DeleteClient(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, ErrCodeInvalidClient, "client not found")
			return
		}
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to delete client")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
