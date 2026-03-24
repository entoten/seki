package scim

// SCIM 2.0 schema URIs.
const (
	UserSchema    = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema   = "urn:ietf:params:scim:schemas:core:2.0:Group"
	ListSchema    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	PatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ErrorSchema   = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// SCIMUser is the SCIM 2.0 User resource (RFC 7643 section 4.1).
type SCIMUser struct {
	Schemas     []string       `json:"schemas"`
	ID          string         `json:"id"`
	ExternalID  string         `json:"externalId,omitempty"`
	UserName    string         `json:"userName"`
	Name        *SCIMName      `json:"name,omitempty"`
	DisplayName string         `json:"displayName,omitempty"`
	Emails      []SCIMEmail    `json:"emails,omitempty"`
	Active      bool           `json:"active"`
	Groups      []SCIMGroupRef `json:"groups,omitempty"`
	Meta        SCIMMeta       `json:"meta"`
}

// SCIMName represents a user's name components.
type SCIMName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// SCIMEmail represents one email address within a SCIM user.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMGroupRef is a reference to a group the user belongs to.
type SCIMGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMMeta contains resource metadata (RFC 7643 section 3.1).
type SCIMMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Location     string `json:"location"`
}

// SCIMGroup is the SCIM 2.0 Group resource (RFC 7643 section 4.2).
type SCIMGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id"`
	DisplayName string       `json:"displayName"`
	Members     []SCIMMember `json:"members,omitempty"`
	Meta        SCIMMeta     `json:"meta"`
}

// SCIMMember is a reference to a member within a SCIM group.
type SCIMMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMListResponse is the SCIM 2.0 list response envelope (RFC 7644 section 3.4.2).
type SCIMListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    any      `json:"Resources"`
}

// SCIMError is the SCIM 2.0 error response (RFC 7644 section 3.12).
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
}

// SCIMPatchRequest represents a SCIM PATCH request body (RFC 7644 section 3.5.2).
type SCIMPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []SCIMPatchOp `json:"Operations"`
}

// SCIMPatchOp is a single SCIM PATCH operation.
type SCIMPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}
