// seki-cli is a command-line tool for managing a seki identity server.
package main

import (
	"fmt"
	"os"
)

var version = "0.1.0-dev"

const usage = `Usage: seki-cli <command> [options]

Commands:
  version     Show version
  keygen      Generate Ed25519 signing key pair
  init        Generate seki.yaml template
  user        User management (list, create, get, delete)
  org         Organization management (list, create, get, delete)
  client      Client management (list, create, delete)
  audit       View audit logs
  migrate     Run database migrations

Global flags:
  --api-url   API base URL (default: http://localhost:8080, env: SEKI_API_URL)
  --api-key   API key for authentication (env: SEKI_API_KEY)
  --json      Output as JSON instead of table
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 1
	}

	// Parse global flags by scanning args before the subcommand.
	apiURL := envDefault("SEKI_API_URL", "http://localhost:8080")
	apiKey := os.Getenv("SEKI_API_KEY")
	jsonOutput := false

	// Consume global flags from the front of args.
	var command string
	var cmdArgs []string
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--api-url":
			if i+1 < len(args) {
				apiURL = args[i+1]
				i += 2
				continue
			}
			fmt.Fprintln(os.Stderr, "error: --api-url requires a value")
			return 1
		case "--api-key":
			if i+1 < len(args) {
				apiKey = args[i+1]
				i += 2
				continue
			}
			fmt.Fprintln(os.Stderr, "error: --api-key requires a value")
			return 1
		case "--json":
			jsonOutput = true
			i++
			continue
		default:
			// First non-flag argument is the command.
			command = args[i]
			cmdArgs = args[i+1:]
			i = len(args) // break
		}
	}

	if command == "" {
		fmt.Fprint(os.Stderr, usage)
		return 1
	}

	switch command {
	case "version":
		runVersion()
	case "keygen":
		runKeygen(cmdArgs)
	case "init":
		runInit(cmdArgs)
	case "user":
		runUser(cmdArgs, apiURL, apiKey, jsonOutput)
	case "org":
		runOrg(cmdArgs, apiURL, apiKey, jsonOutput)
	case "client":
		runClient(cmdArgs)
	case "audit":
		runAudit(cmdArgs, apiURL, apiKey, jsonOutput)
	case "migrate":
		runMigrate(cmdArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		fmt.Fprint(os.Stderr, usage)
		return 1
	}

	return 0
}

// envDefault returns the value of the environment variable key, or fallback if unset.
func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
