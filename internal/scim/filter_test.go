package scim

import (
	"testing"
)

func TestParseFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		wantAttr string
		wantOp   string
		wantVal  string
	}{
		{"empty", "", true, "", "", ""},
		{"too few parts", "userName eq", true, "", "", ""},
		{"eq filter", `userName eq "alice@example.com"`, false, "userName", "eq", "alice@example.com"},
		{"co filter", `displayName co "John"`, false, "displayName", "co", "John"},
		{"sw filter", `userName sw "admin"`, false, "userName", "sw", "admin"},
		{"unsupported op", `userName ne "test"`, true, "", "", ""},
		{"case insensitive op", `userName EQ "test"`, false, "userName", "eq", "test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseFilter(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil filter")
			}
			if got.Attribute != tt.wantAttr {
				t.Errorf("Attribute = %q, want %q", got.Attribute, tt.wantAttr)
			}
			if got.Operator != tt.wantOp {
				t.Errorf("Operator = %q, want %q", got.Operator, tt.wantOp)
			}
			if got.Value != tt.wantVal {
				t.Errorf("Value = %q, want %q", got.Value, tt.wantVal)
			}
		})
	}
}

func TestFilterMatchesUser(t *testing.T) {
	user := &SCIMUser{
		UserName:    "alice@example.com",
		DisplayName: "Alice Smith",
		ExternalID:  "ext-123",
		Emails: []SCIMEmail{
			{Value: "alice@example.com", Type: "work", Primary: true},
		},
	}

	tests := []struct {
		name   string
		filter *FilterOp
		want   bool
	}{
		{"nil filter matches all", nil, true},
		{"eq username match", &FilterOp{"userName", "eq", "alice@example.com"}, true},
		{"eq username no match", &FilterOp{"userName", "eq", "bob@example.com"}, false},
		{"co displayName match", &FilterOp{"displayName", "co", "alice"}, true},
		{"co displayName no match", &FilterOp{"displayName", "co", "bob"}, false},
		{"sw username match", &FilterOp{"userName", "sw", "alice"}, true},
		{"sw username no match", &FilterOp{"userName", "sw", "bob"}, false},
		{"eq externalid match", &FilterOp{"externalId", "eq", "ext-123"}, true},
		{"emails.value match", &FilterOp{"emails.value", "eq", "alice@example.com"}, true},
		{"emails.value no match", &FilterOp{"emails.value", "eq", "bob@example.com"}, false},
		{"unknown attr", &FilterOp{"unknown", "eq", "test"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.filter.MatchesUser(user)
			if got != tt.want {
				t.Errorf("MatchesUser = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchString(t *testing.T) {
	if !matchString("Hello World", "co", "hello") {
		t.Error("expected case-insensitive co match")
	}
	if matchString("Hello", "eq", "world") {
		t.Error("unexpected eq match")
	}
	if !matchString("Hello", "sw", "he") {
		t.Error("expected sw match")
	}
	if matchString("Hello", "gt", "a") {
		t.Error("unexpected match for unsupported op")
	}
}
