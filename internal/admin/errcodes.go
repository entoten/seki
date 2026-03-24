package admin

// Error code constants for machine-readable error identification.
// These are used in ProblemDetail responses across the admin, OIDC, and SCIM APIs.
const (
	ErrCodeInvalidRequest     = "INVALID_REQUEST"
	ErrCodeInvalidRedirectURI = "INVALID_REDIRECT_URI"
	ErrCodeInvalidClient      = "INVALID_CLIENT"
	ErrCodeInvalidGrant       = "INVALID_GRANT"
	ErrCodeTokenExpired       = "TOKEN_EXPIRED"
	ErrCodeUserNotFound       = "USER_NOT_FOUND"
	ErrCodeOrgNotFound        = "ORG_NOT_FOUND"
	ErrCodeConflict           = "CONFLICT"
	ErrCodeRateLimited        = "RATE_LIMITED"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeInternalError      = "INTERNAL_ERROR"
)
