package passkey

import (
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/entoten/seki/internal/storage"
)

// UserAdapter wraps a storage.User and its credentials to satisfy the
// webauthn.User interface. The WebAuthnID is derived from the user's stable
// UUID (the storage ID), NOT from the email, per WebAuthn best practices.
type UserAdapter struct {
	user        *storage.User
	credentials []webauthn.Credential
}

// NewUserAdapter creates a UserAdapter from a storage user and a set of
// storage credentials. It converts storage.Credential entries into
// webauthn.Credential entries.
func NewUserAdapter(user *storage.User, creds []*storage.Credential) *UserAdapter {
	wanCreds := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		wanCreds = append(wanCreds, storageCredToWebAuthn(c))
	}
	return &UserAdapter{
		user:        user,
		credentials: wanCreds,
	}
}

// WebAuthnID returns a stable, immutable byte ID for the user. We use the
// user's storage ID (a UUID string) as bytes. This is NOT the email.
func (u *UserAdapter) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

// WebAuthnName returns the user's email as the human-readable identifier.
func (u *UserAdapter) WebAuthnName() string {
	return u.user.Email
}

// WebAuthnDisplayName returns the user's display name.
func (u *UserAdapter) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.Email
}

// WebAuthnCredentials returns all WebAuthn credentials for this user.
func (u *UserAdapter) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// storageCredToWebAuthn converts a storage.Credential to a webauthn.Credential.
func storageCredToWebAuthn(c *storage.Credential) webauthn.Credential {
	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

// Compile-time check that UserAdapter satisfies webauthn.User.
var _ webauthn.User = (*UserAdapter)(nil)
