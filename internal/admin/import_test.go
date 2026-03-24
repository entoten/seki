package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entoten/seki/internal/storage"
	_ "github.com/entoten/seki/internal/storage/sqlite"
)

type importReport struct {
	Created int           `json:"created"`
	Skipped int           `json:"skipped"`
	Errors  []importError `json:"errors"`
	Total   int           `json:"total"`
}

type importError struct {
	Line  int    `json:"line"`
	Email string `json:"email"`
	Error string `json:"error"`
}

func TestImportJSONCreatesUsers(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `[
		{"email":"import1@example.com","display_name":"Import One"},
		{"email":"import2@example.com","display_name":"Import Two"}
	]`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var report importReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Created != 2 {
		t.Fatalf("expected 2 created, got %d", report.Created)
	}
	if report.Total != 2 {
		t.Fatalf("expected total 2, got %d", report.Total)
	}
}

func TestImportJSONSkipsExisting(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Create a user first.
	createBody := `{"email":"existing@example.com","display_name":"Existing"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString(createBody))
	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("pre-create: expected 201, got %d", createRec.Code)
	}

	// Import with existing + new user.
	body := `[
		{"email":"existing@example.com","display_name":"Existing"},
		{"email":"new@example.com","display_name":"New"}
	]`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var report importReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Created != 1 {
		t.Fatalf("expected 1 created, got %d", report.Created)
	}
	if report.Skipped != 1 {
		t.Fatalf("expected 1 skipped, got %d", report.Skipped)
	}
}

func TestImportJSONWithPasswordHash(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `[{"email":"hashed@example.com","display_name":"Hashed","password_hash":"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}]`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var report importReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Created != 1 {
		t.Fatalf("expected 1 created, got %d", report.Created)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", report.Errors)
	}
}

func TestImportJSONDryRunDoesNotCreate(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `[{"email":"dryrun@example.com","display_name":"DryRun"}]`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/users", bytes.NewBufferString(body))
	req.Header.Set("X-Dry-Run", "true")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var report importReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Created != 1 {
		t.Fatalf("expected 1 created in report, got %d", report.Created)
	}

	// Verify user was NOT actually created.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/users?email=dryrun@example.com", nil)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)

	var listResp struct {
		Users []storage.User `json:"users"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listResp.Users) != 0 {
		t.Fatal("dry run should not have created the user")
	}
}

func TestImportCSVWorks(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	csvData := "email,display_name,password_hash\ncsv1@example.com,CSV One,\ncsv2@example.com,CSV Two,\n"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/users/csv", bytes.NewBufferString(csvData))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var report importReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Created != 2 {
		t.Fatalf("expected 2 created, got %d", report.Created)
	}
	if report.Total != 2 {
		t.Fatalf("expected total 2, got %d", report.Total)
	}
}

func TestImportCSVMissingFields(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// CSV with only email column — display_name and password_hash missing.
	csvData := "email\nminimal@example.com\n"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/users/csv", bytes.NewBufferString(csvData))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var report importReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Created != 1 {
		t.Fatalf("expected 1 created, got %d", report.Created)
	}
}

func TestImportJSONErrorReportForInvalidEmail(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	body := `[
		{"email":"valid@example.com","display_name":"Valid"},
		{"email":"bad","display_name":"Bad Email"},
		{"email":"also-valid@example.com","display_name":"Also Valid"}
	]`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/users", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var report importReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Created != 2 {
		t.Fatalf("expected 2 created, got %d", report.Created)
	}
	if len(report.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(report.Errors))
	}
	if report.Errors[0].Line != 2 {
		t.Fatalf("expected error on line 2, got %d", report.Errors[0].Line)
	}
	if report.Errors[0].Email != "bad" {
		t.Fatalf("expected email 'bad', got %s", report.Errors[0].Email)
	}
}

func TestImportJSONMaxLimitEnforcement(t *testing.T) {
	h := setupHandler(t)
	mux := newMux(h)

	// Build a JSON array that exceeds the 10,000 user limit.
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < 10001; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"email":"user` + strings.Repeat("x", 5) + `@example.com","display_name":"U"}`)
	}
	sb.WriteString("]")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/import/users", bytes.NewBufferString(sb.String()))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
