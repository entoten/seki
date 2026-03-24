package scim

import (
	"testing"
)

// FuzzSCIMFilterParsing fuzzes the SCIM filter parser with random filter strings.
// The main assertion is that ParseFilter never panics on any input.
func FuzzSCIMFilterParsing(f *testing.F) {
	// Valid filters.
	f.Add(`userName eq "john@test.com"`)
	f.Add(`displayName co "John"`)
	f.Add(`userName sw "j"`)
	f.Add(`externalId eq "ext-123"`)
	f.Add(`emails.value eq "user@example.com"`)

	// Edge cases.
	f.Add(``)
	f.Add(`invalid`)
	f.Add(`userName eq ""`)
	f.Add(`userName`)
	f.Add(`userName eq`)
	f.Add(`a b c d e`)
	f.Add(`userName INVALID "value"`)
	f.Add(`   userName   eq   "john"   `)
	f.Add(`userName eq "value with spaces and \"quotes\""`)
	f.Add(`a eq "` + string(make([]byte, 1000)) + `"`)
	f.Add("\x00\x01\x02")
	f.Add(`userName eq "val" and displayName co "test"`)

	f.Fuzz(func(t *testing.T, filter string) {
		// Should never panic regardless of input.
		result := ParseFilter(filter)

		// If we get a result, validate it has reasonable fields.
		if result != nil {
			if result.Attribute == "" {
				t.Errorf("parsed filter has empty attribute for input: %q", filter)
			}
			if result.Operator == "" {
				t.Errorf("parsed filter has empty operator for input: %q", filter)
			}
			// Operator must be one of the supported ones.
			switch result.Operator {
			case "eq", "co", "sw":
				// valid
			default:
				t.Errorf("parsed filter has unexpected operator %q for input: %q", result.Operator, filter)
			}
		}
	})
}
