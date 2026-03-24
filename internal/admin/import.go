package admin

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/validate"
)

// maxImportUsers is the maximum number of users allowed in a single import request.
const maxImportUsers = 10000

// maxImportBodyBytes is the body size limit for import endpoints (50 MiB).
const maxImportBodyBytes = 50 << 20

// importUserRecord represents a single user row in a bulk import request.
type importUserRecord struct {
	Email        string          `json:"email"`
	DisplayName  string          `json:"display_name"`
	PasswordHash string          `json:"password_hash"`
	Metadata     json.RawMessage `json:"metadata"`
}

// importReport is the JSON response for a bulk import operation.
type importReport struct {
	Created int           `json:"created"`
	Skipped int           `json:"skipped"`
	Errors  []importError `json:"errors"`
	Total   int           `json:"total"`
}

// importError describes a single error encountered during import.
type importError struct {
	Line  int    `json:"line"`
	Email string `json:"email"`
	Error string `json:"error"`
}

// registerImportRoutesOn registers the bulk import API routes.
func (h *Handler) registerImportRoutesOn(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/import/users", h.handleImportUsersJSON)
	mux.HandleFunc("POST /api/v1/import/users/csv", h.handleImportUsersCSV)
}

// handleImportUsersJSON handles POST /api/v1/import/users (JSON bulk import).
func (h *Handler) handleImportUsersJSON(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBodyBytes)

	var records []importUserRecord
	if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	if len(records) > maxImportUsers {
		writeProblem(w, http.StatusBadRequest, fmt.Sprintf("too many users: %d exceeds maximum of %d", len(records), maxImportUsers))
		return
	}

	dryRun := strings.EqualFold(r.Header.Get("X-Dry-Run"), "true")
	report := h.processImport(r, records, dryRun)
	writeJSON(w, http.StatusOK, report)
}

// handleImportUsersCSV handles POST /api/v1/import/users/csv (CSV bulk import).
func (h *Handler) handleImportUsersCSV(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBodyBytes)

	reader := csv.NewReader(r.Body)
	reader.TrimLeadingSpace = true

	// Read header row.
	header, err := reader.Read()
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "failed to read CSV header: "+err.Error())
		return
	}

	colIndex := make(map[string]int, len(header))
	for i, col := range header {
		colIndex[strings.TrimSpace(strings.ToLower(col))] = i
	}

	emailIdx, hasEmail := colIndex["email"]
	if !hasEmail {
		writeProblem(w, http.StatusBadRequest, "CSV must have an 'email' column")
		return
	}
	displayNameIdx, hasDisplayName := colIndex["display_name"]
	passwordHashIdx, hasPasswordHash := colIndex["password_hash"]

	var records []importUserRecord
	lineNum := 1 // header is line 1, data starts at line 2
	for {
		lineNum++
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeProblem(w, http.StatusBadRequest, fmt.Sprintf("CSV parse error at line %d: %s", lineNum, err.Error()))
			return
		}

		rec := importUserRecord{}
		if emailIdx < len(row) {
			rec.Email = strings.TrimSpace(row[emailIdx])
		}
		if hasDisplayName && displayNameIdx < len(row) {
			rec.DisplayName = strings.TrimSpace(row[displayNameIdx])
		}
		if hasPasswordHash && passwordHashIdx < len(row) {
			rec.PasswordHash = strings.TrimSpace(row[passwordHashIdx])
		}

		records = append(records, rec)
	}

	if len(records) > maxImportUsers {
		writeProblem(w, http.StatusBadRequest, fmt.Sprintf("too many users: %d exceeds maximum of %d", len(records), maxImportUsers))
		return
	}

	dryRun := strings.EqualFold(r.Header.Get("X-Dry-Run"), "true")
	report := h.processImport(r, records, dryRun)
	writeJSON(w, http.StatusOK, report)
}

// processImport validates and creates users from a list of import records.
func (h *Handler) processImport(r *http.Request, records []importUserRecord, dryRun bool) importReport {
	report := importReport{
		Total:  len(records),
		Errors: []importError{},
	}

	for i, rec := range records {
		line := i + 1

		// Validate email.
		if err := validate.Email(rec.Email); err != nil {
			report.Errors = append(report.Errors, importError{
				Line:  line,
				Email: rec.Email,
				Error: err.Error(),
			})
			continue
		}

		// Validate display name.
		if err := validate.DisplayName(rec.DisplayName); err != nil {
			report.Errors = append(report.Errors, importError{
				Line:  line,
				Email: rec.Email,
				Error: err.Error(),
			})
			continue
		}

		// Validate metadata.
		if err := validate.Metadata(rec.Metadata); err != nil {
			report.Errors = append(report.Errors, importError{
				Line:  line,
				Email: rec.Email,
				Error: err.Error(),
			})
			continue
		}

		// Validate password hash format if provided.
		if rec.PasswordHash != "" {
			if !isValidPasswordHash(rec.PasswordHash) {
				report.Errors = append(report.Errors, importError{
					Line:  line,
					Email: rec.Email,
					Error: "unsupported password hash format (must be bcrypt $2a$/$2b$ or argon2id $argon2id$)",
				})
				continue
			}
		}

		// Check if user already exists.
		_, err := h.store.GetUserByEmail(r.Context(), rec.Email)
		if err == nil {
			// User exists, skip.
			report.Skipped++
			continue
		}
		if !errors.Is(err, storage.ErrNotFound) {
			report.Errors = append(report.Errors, importError{
				Line:  line,
				Email: rec.Email,
				Error: "storage error: " + err.Error(),
			})
			continue
		}

		if dryRun {
			report.Created++
			continue
		}

		now := time.Now().UTC().Truncate(time.Second)
		user := &storage.User{
			ID:          uuid.New().String(),
			Email:       rec.Email,
			DisplayName: rec.DisplayName,
			Metadata:    rec.Metadata,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if len(user.Metadata) == 0 {
			user.Metadata = json.RawMessage(`{}`)
		}

		if err := h.store.CreateUser(r.Context(), user); err != nil {
			if errors.Is(err, storage.ErrAlreadyExists) {
				report.Skipped++
				continue
			}
			report.Errors = append(report.Errors, importError{
				Line:  line,
				Email: rec.Email,
				Error: "failed to create user: " + err.Error(),
			})
			continue
		}

		// If a password hash was provided, store it as a credential.
		if rec.PasswordHash != "" {
			cred := &storage.Credential{
				ID:        uuid.New().String(),
				UserID:    user.ID,
				Type:      "password",
				Secret:    []byte(rec.PasswordHash),
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := h.store.CreateCredential(r.Context(), cred); err != nil {
				report.Errors = append(report.Errors, importError{
					Line:  line,
					Email: rec.Email,
					Error: "user created but failed to store password hash: " + err.Error(),
				})
				// User was still created, so count it.
				report.Created++
				continue
			}
		}

		report.Created++
	}

	return report
}

// isValidPasswordHash checks whether the hash string is a recognized format.
func isValidPasswordHash(hash string) bool {
	// bcrypt: $2a$ or $2b$ prefix
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") {
		return true
	}
	// argon2id: $argon2id$ prefix
	if strings.HasPrefix(hash, "$argon2id$") {
		return true
	}
	return false
}
