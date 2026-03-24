package scim

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/entoten/seki/internal/storage"
)

func TestUserToSCIM(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	user := &storage.User{
		ID:          "usr-123",
		Email:       "test@example.com",
		DisplayName: "John Doe",
		Disabled:    false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	su := UserToSCIM(user, "https://auth.example.com")

	if su.ID != "usr-123" {
		t.Errorf("ID = %q", su.ID)
	}
	if su.UserName != "test@example.com" {
		t.Errorf("UserName = %q", su.UserName)
	}
	if su.DisplayName != "John Doe" {
		t.Errorf("DisplayName = %q", su.DisplayName)
	}
	if !su.Active {
		t.Error("expected Active = true")
	}
	if su.Name == nil {
		t.Fatal("expected Name to be set for space-separated display name")
	}
	if su.Name.GivenName != "John" || su.Name.FamilyName != "Doe" {
		t.Errorf("Name = %v", su.Name)
	}
	if su.Meta.ResourceType != "User" {
		t.Errorf("Meta.ResourceType = %q", su.Meta.ResourceType)
	}
	if su.Meta.Location != "https://auth.example.com/scim/v2/Users/usr-123" {
		t.Errorf("Meta.Location = %q", su.Meta.Location)
	}
	if len(su.Emails) != 1 || su.Emails[0].Value != "test@example.com" {
		t.Errorf("Emails = %v", su.Emails)
	}
}

func TestUserToSCIM_DisabledUser(t *testing.T) {
	user := &storage.User{
		ID:        "usr-456",
		Email:     "disabled@example.com",
		Disabled:  true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	su := UserToSCIM(user, "https://auth.example.com")
	if su.Active {
		t.Error("expected Active = false for disabled user")
	}
}

func TestUserToSCIM_SingleWordName(t *testing.T) {
	user := &storage.User{
		ID:          "usr-789",
		Email:       "single@example.com",
		DisplayName: "Alice",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	su := UserToSCIM(user, "https://auth.example.com")
	if su.Name != nil {
		t.Errorf("expected nil Name for single-word display name, got %v", su.Name)
	}
}

func TestSCIMToUser(t *testing.T) {
	su := &SCIMUser{
		UserName:    "new@example.com",
		DisplayName: "New User",
		Active:      true,
	}

	user := SCIMToUser(su)
	if user.Email != "new@example.com" {
		t.Errorf("Email = %q", user.Email)
	}
	if user.DisplayName != "New User" {
		t.Errorf("DisplayName = %q", user.DisplayName)
	}
	if user.Disabled {
		t.Error("expected Disabled = false")
	}
	if user.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestSCIMToUser_FromEmails(t *testing.T) {
	su := &SCIMUser{
		Emails: []SCIMEmail{
			{Value: "primary@example.com", Primary: true},
			{Value: "secondary@example.com"},
		},
	}

	user := SCIMToUser(su)
	if user.Email != "primary@example.com" {
		t.Errorf("Email = %q, want primary email", user.Email)
	}
}

func TestSCIMToUser_FromName(t *testing.T) {
	su := &SCIMUser{
		UserName: "nametest@example.com",
		Name: &SCIMName{
			GivenName:  "Jane",
			FamilyName: "Doe",
		},
	}

	user := SCIMToUser(su)
	if user.DisplayName != "Jane Doe" {
		t.Errorf("DisplayName = %q", user.DisplayName)
	}
}

func TestOrgToSCIMGroup(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	org := &storage.Organization{
		ID:        "org-123",
		Slug:      "eng",
		Name:      "Engineering",
		Domains:   []string{},
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	}
	members := []*storage.OrgMember{
		{OrgID: "org-123", UserID: "usr-1", Role: "admin"},
		{OrgID: "org-123", UserID: "usr-2", Role: "member"},
	}

	g := OrgToSCIMGroup(org, members, "https://auth.example.com")

	if g.ID != "org-123" {
		t.Errorf("ID = %q", g.ID)
	}
	if g.DisplayName != "Engineering" {
		t.Errorf("DisplayName = %q", g.DisplayName)
	}
	if g.Meta.ResourceType != "Group" {
		t.Errorf("Meta.ResourceType = %q", g.Meta.ResourceType)
	}
	if len(g.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(g.Members))
	}
	if g.Members[0].Value != "usr-1" {
		t.Errorf("member 0 value = %q", g.Members[0].Value)
	}
}
