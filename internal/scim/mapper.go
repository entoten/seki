package scim

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/entoten/seki/internal/storage"
)

// UserToSCIM converts a seki User to a SCIM User resource.
func UserToSCIM(user *storage.User, baseURL string) *SCIMUser {
	su := &SCIMUser{
		Schemas:     []string{UserSchema},
		ID:          user.ID,
		UserName:    user.Email,
		DisplayName: user.DisplayName,
		Active:      !user.Disabled,
		Emails: []SCIMEmail{
			{Value: user.Email, Type: "work", Primary: true},
		},
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      user.CreatedAt.UTC().Format(time.RFC3339),
			LastModified: user.UpdatedAt.UTC().Format(time.RFC3339),
			Location:     fmt.Sprintf("%s/scim/v2/Users/%s", strings.TrimRight(baseURL, "/"), user.ID),
		},
	}

	// If display name has a space, split into given/family name.
	if parts := strings.SplitN(user.DisplayName, " ", 2); len(parts) == 2 {
		su.Name = &SCIMName{
			GivenName:  parts[0],
			FamilyName: parts[1],
		}
	}

	return su
}

// SCIMToUser converts a SCIM User resource into a new seki User.
func SCIMToUser(su *SCIMUser) *storage.User {
	now := time.Now().UTC().Truncate(time.Second)

	email := su.UserName
	// Prefer primary email if userName is empty.
	if email == "" {
		for _, e := range su.Emails {
			if e.Primary {
				email = e.Value
				break
			}
		}
		// Fall back to first email.
		if email == "" && len(su.Emails) > 0 {
			email = su.Emails[0].Value
		}
	}

	displayName := su.DisplayName
	if displayName == "" && su.Name != nil {
		displayName = strings.TrimSpace(su.Name.GivenName + " " + su.Name.FamilyName)
	}

	user := &storage.User{
		ID:          uuid.New().String(),
		Email:       email,
		DisplayName: displayName,
		Disabled:    !su.Active,
		Metadata:    json.RawMessage(`{}`),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	return user
}

// OrgToSCIMGroup converts a seki Organization and its members to a SCIM Group resource.
func OrgToSCIMGroup(org *storage.Organization, members []*storage.OrgMember, baseURL string) *SCIMGroup {
	base := strings.TrimRight(baseURL, "/")
	g := &SCIMGroup{
		Schemas:     []string{GroupSchema},
		ID:          org.ID,
		DisplayName: org.Name,
		Meta: SCIMMeta{
			ResourceType: "Group",
			Created:      org.CreatedAt.UTC().Format(time.RFC3339),
			LastModified: org.UpdatedAt.UTC().Format(time.RFC3339),
			Location:     fmt.Sprintf("%s/scim/v2/Groups/%s", base, org.ID),
		},
	}

	for _, m := range members {
		g.Members = append(g.Members, SCIMMember{
			Value: m.UserID,
			Ref:   fmt.Sprintf("%s/scim/v2/Users/%s", base, m.UserID),
		})
	}

	return g
}
