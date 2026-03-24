package scim

import (
	"strings"
)

// FilterOp represents a parsed SCIM filter operation.
type FilterOp struct {
	Attribute string // e.g. "userName", "displayName"
	Operator  string // e.g. "eq", "co", "sw"
	Value     string // the comparison value (unquoted)
}

// ParseFilter parses a minimal SCIM filter expression.
// Supports: attr op "value"
// Examples:
//
//	userName eq "john@example.com"
//	displayName co "John"
func ParseFilter(filter string) *FilterOp {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil
	}

	// Split into exactly 3 parts: attribute operator "value"
	parts := strings.SplitN(filter, " ", 3)
	if len(parts) < 3 {
		return nil
	}

	attr := parts[0]
	op := strings.ToLower(parts[1])
	val := parts[2]

	// Strip surrounding quotes from value.
	val = strings.Trim(val, `"`)

	switch op {
	case "eq", "co", "sw":
		return &FilterOp{
			Attribute: attr,
			Operator:  op,
			Value:     val,
		}
	default:
		return nil
	}
}

// MatchesUser checks whether a SCIM User matches the filter.
func (f *FilterOp) MatchesUser(u *SCIMUser) bool {
	if f == nil {
		return true
	}

	var fieldValue string
	switch strings.ToLower(f.Attribute) {
	case "username":
		fieldValue = u.UserName
	case "displayname":
		fieldValue = u.DisplayName
	case "externalid":
		fieldValue = u.ExternalID
	default:
		// Check emails
		if strings.ToLower(f.Attribute) == "emails.value" {
			for _, e := range u.Emails {
				if matchString(e.Value, f.Operator, f.Value) {
					return true
				}
			}
			return false
		}
		return false
	}

	return matchString(fieldValue, f.Operator, f.Value)
}

func matchString(fieldValue, op, filterValue string) bool {
	fv := strings.ToLower(fieldValue)
	cv := strings.ToLower(filterValue)

	switch op {
	case "eq":
		return fv == cv
	case "co":
		return strings.Contains(fv, cv)
	case "sw":
		return strings.HasPrefix(fv, cv)
	default:
		return false
	}
}
