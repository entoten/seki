package oidc

// ACR (Authentication Context Class Reference) constants define the
// authentication assurance levels supported by Seki.
const (
	// ACRBasic indicates authentication via password or social login only.
	ACRBasic = "urn:seki:acr:basic"

	// ACRMFA indicates the user completed multi-factor authentication
	// (e.g. TOTP, passkey, or another second factor).
	ACRMFA = "urn:seki:acr:mfa"
)
