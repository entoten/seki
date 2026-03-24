package validate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLimitedReader(t *testing.T) {
	body := strings.NewReader("hello world")
	req := httptest.NewRequest(http.MethodPost, "/", body)

	lr := LimitedReader(req)
	if lr == nil {
		t.Fatal("expected non-nil reader")
	}
	lr.Close()
}

func TestLimitBody(t *testing.T) {
	body := strings.NewReader("test body")
	req := httptest.NewRequest(http.MethodPost, "/", body)

	LimitBody(req)
	if req.Body == nil {
		t.Fatal("expected body to be replaced")
	}
}
