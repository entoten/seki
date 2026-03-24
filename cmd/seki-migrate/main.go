// seki-migrate imports users, clients, and roles from Auth0, Keycloak, Okta, or Clerk into seki.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/entoten/seki/internal/migrate"
	"github.com/entoten/seki/pkg/client"
)

var version = "0.1.0-dev"

const usage = `Usage: seki-migrate <source> [options]

Sources:
  auth0      Import from Auth0 export
  keycloak   Import from Keycloak realm export
  okta       Import from Okta Management API export
  clerk      Import from Clerk Backend API export

Options:
  --file FILE        Export file path (JSON)
  --api-url URL      seki API URL (default: http://localhost:8080)
  --api-key KEY      seki API key
  --dry-run          Show what would be imported without making changes
  --skip-passwords   Skip password hash migration
  --verbose          Detailed output
  --version          Show version
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 1
	}

	var (
		source        string
		filePath      string
		apiURL        = envDefault("SEKI_API_URL", "http://localhost:8080")
		apiKey        = os.Getenv("SEKI_API_KEY")
		dryRun        bool
		skipPasswords bool
		verbose       bool
	)

	i := 0
	for i < len(args) {
		switch args[i] {
		case "--file":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --file requires a value")
				return 1
			}
			filePath = args[i+1]
			i += 2
		case "--api-url":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --api-url requires a value")
				return 1
			}
			apiURL = args[i+1]
			i += 2
		case "--api-key":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --api-key requires a value")
				return 1
			}
			apiKey = args[i+1]
			i += 2
		case "--dry-run":
			dryRun = true
			i++
		case "--skip-passwords":
			skipPasswords = true
			i++
		case "--verbose":
			verbose = true
			i++
		case "--version":
			fmt.Println("seki-migrate", version)
			return 0
		case "--help", "-h":
			fmt.Print(usage)
			return 0
		default:
			if source == "" && !isFlag(args[i]) {
				source = args[i]
				i++
			} else {
				fmt.Fprintf(os.Stderr, "unknown option: %s\n", args[i])
				return 1
			}
		}
	}

	if source == "" {
		fmt.Fprintln(os.Stderr, "error: source is required (auth0, keycloak, okta, or clerk)")
		fmt.Fprint(os.Stderr, usage)
		return 1
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "error: --file is required")
		return 1
	}

	if apiKey == "" && !dryRun {
		fmt.Fprintln(os.Stderr, "warning: no API key provided; set --api-key or SEKI_API_KEY")
	}

	apiClient := client.New(apiURL, apiKey)
	cfg := migrate.Config{
		APIClient:     apiClient,
		DryRun:        dryRun,
		SkipPasswords: skipPasswords,
		Verbose:       verbose,
	}

	ctx := context.Background()
	var importer migrate.Importer

	switch source {
	case "auth0":
		export, err := migrate.ParseAuth0Export(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing Auth0 export: %v\n", err)
			return 1
		}
		importer = migrate.NewAuth0Importer(export, cfg, os.Stdout)

	case "keycloak":
		export, err := migrate.ParseKeycloakExport(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing Keycloak export: %v\n", err)
			return 1
		}
		importer = migrate.NewKeycloakImporter(export, cfg, os.Stdout)

	case "okta":
		export, err := migrate.ParseOktaExport(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing Okta export: %v\n", err)
			return 1
		}
		importer = migrate.NewOktaImporter(export, cfg, os.Stdout)

	case "clerk":
		export, err := migrate.ParseClerkExport(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing Clerk export: %v\n", err)
			return 1
		}
		importer = migrate.NewClerkImporter(export, cfg, os.Stdout)

	default:
		fmt.Fprintf(os.Stderr, "unknown source: %s (expected auth0, keycloak, okta, or clerk)\n", source)
		return 1
	}

	result, err := importer.Import(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
		return 1
	}

	if !dryRun {
		fmt.Println()
		fmt.Println("Migration complete.")
		fmt.Println(result.Summary())
	}

	if len(result.Errors) > 0 {
		return 1
	}
	return 0
}

func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
