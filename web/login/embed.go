package login

import "embed"

// Templates holds the embedded login HTML templates.
//
//go:embed templates/*.html
var Templates embed.FS
