package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Monet/seki/pkg/client"
)

// runVersion prints the CLI version.
func runVersion() {
	fmt.Printf("seki-cli v%s\n", version)
}

// runKeygen generates an Ed25519 signing key pair.
func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	output := fs.String("output", "signing.key", "file path for the private key")
	fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("generating key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fatalf("marshaling private key: %v", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	if err := os.WriteFile(*output, pem.EncodeToMemory(block), 0600); err != nil {
		fatalf("writing key file: %v", err)
	}

	fmt.Printf("Private key written to: %s\n", *output)
	fmt.Printf("Algorithm: Ed25519\n")
	fmt.Printf("Public key (raw hex): %x\n", pub)
}

// runInit generates a seki.yaml configuration template.
func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	nonInteractive := fs.Bool("non-interactive", false, "output default template without prompts")
	fs.Parse(args)

	issuer := "http://localhost:8080"
	driver := "sqlite"
	dsn := "seki.db"
	address := ":8080"

	if !*nonInteractive {
		reader := bufio.NewReader(os.Stdin)
		issuer = prompt(reader, "Issuer URL", issuer)
		driver = prompt(reader, "Database driver (sqlite/postgres)", driver)
		if driver == "postgres" {
			dsn = prompt(reader, "Database DSN", "postgres://localhost:5432/seki?sslmode=disable")
		} else {
			dsn = prompt(reader, "Database file", dsn)
		}
		address = prompt(reader, "Listen address", address)
	}

	tmpl := fmt.Sprintf(`server:
  address: "%s"
  issuer: "%s"

database:
  driver: "%s"
  dsn: "%s"

signing:
  algorithm: EdDSA
  key_file: signing.key

authentication:
  password:
    enabled: true

session:
  max_concurrent_sessions: 0

audit:
  output: stdout
  retention_days: 90

admin:
  api_keys: []
`, address, issuer, driver, dsn)

	if err := os.WriteFile("seki.yaml", []byte(tmpl), 0600); err != nil {
		fatalf("writing seki.yaml: %v", err)
	}

	fmt.Println("seki.yaml written successfully.")
}

// prompt shows a prompt and returns user input or the default.
func prompt(reader *bufio.Reader, label, defaultVal string) string {
	fmt.Printf("%s [%s]: ", label, defaultVal)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

// runUser handles user subcommands.
func runUser(args []string, apiURL, apiKey string, jsonOutput bool) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: seki-cli user <list|create|get|delete> [options]")
		os.Exit(1)
	}

	c := client.New(apiURL, apiKey)
	ctx := context.Background()
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		fs := flag.NewFlagSet("user list", flag.ExitOnError)
		limit := fs.Int("limit", 20, "max number of results")
		fs.Parse(rest)

		result, err := c.ListUsers(ctx, client.ListOptions{Limit: *limit})
		if err != nil {
			fatalf("listing users: %v", err)
		}

		if jsonOutput {
			printJSON(result.Data)
			return
		}

		w := tableWriter()
		fmt.Fprintln(w, "ID\tEMAIL\tNAME\tCREATED")
		for _, u := range result.Data {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.ID, u.Email, u.DisplayName, u.CreatedAt.Format("2006-01-02"))
		}
		w.Flush()

	case "create":
		fs := flag.NewFlagSet("user create", flag.ExitOnError)
		email := fs.String("email", "", "user email (required)")
		name := fs.String("name", "", "display name (required)")
		fs.Parse(rest)

		if *email == "" || *name == "" {
			fmt.Fprintln(os.Stderr, "usage: seki-cli user create --email EMAIL --name NAME")
			os.Exit(1)
		}

		user, err := c.CreateUser(ctx, client.CreateUserInput{
			Email:       *email,
			DisplayName: *name,
		})
		if err != nil {
			fatalf("creating user: %v", err)
		}

		if jsonOutput {
			printJSON(user)
			return
		}

		fmt.Printf("User created: %s (%s)\n", user.ID, user.Email)

	case "get":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: seki-cli user get ID")
			os.Exit(1)
		}

		user, err := c.GetUser(ctx, rest[0])
		if err != nil {
			fatalf("getting user: %v", err)
		}

		if jsonOutput {
			printJSON(user)
			return
		}

		w := tableWriter()
		fmt.Fprintln(w, "ID\tEMAIL\tNAME\tDISABLED\tCREATED")
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\n", user.ID, user.Email, user.DisplayName, user.Disabled, user.CreatedAt.Format("2006-01-02"))
		w.Flush()

	case "delete":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: seki-cli user delete ID")
			os.Exit(1)
		}

		if err := c.DeleteUser(ctx, rest[0]); err != nil {
			fatalf("deleting user: %v", err)
		}

		fmt.Printf("User deleted: %s\n", rest[0])

	default:
		fmt.Fprintf(os.Stderr, "unknown user subcommand: %s\n", sub)
		os.Exit(1)
	}
}

// runOrg handles organization subcommands.
func runOrg(args []string, apiURL, apiKey string, jsonOutput bool) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: seki-cli org <list|create|get|delete> [options]")
		os.Exit(1)
	}

	c := client.New(apiURL, apiKey)
	ctx := context.Background()
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		fs := flag.NewFlagSet("org list", flag.ExitOnError)
		limit := fs.Int("limit", 20, "max number of results")
		fs.Parse(rest)

		result, err := c.ListOrgs(ctx, client.ListOptions{Limit: *limit})
		if err != nil {
			fatalf("listing orgs: %v", err)
		}

		if jsonOutput {
			printJSON(result.Data)
			return
		}

		w := tableWriter()
		fmt.Fprintln(w, "ID\tSLUG\tNAME\tCREATED")
		for _, o := range result.Data {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", o.ID, o.Slug, o.Name, o.CreatedAt.Format("2006-01-02"))
		}
		w.Flush()

	case "create":
		fs := flag.NewFlagSet("org create", flag.ExitOnError)
		slug := fs.String("slug", "", "organization slug (required)")
		name := fs.String("name", "", "organization name (required)")
		fs.Parse(rest)

		if *slug == "" || *name == "" {
			fmt.Fprintln(os.Stderr, "usage: seki-cli org create --slug SLUG --name NAME")
			os.Exit(1)
		}

		org, err := c.CreateOrg(ctx, client.CreateOrgInput{
			Slug: *slug,
			Name: *name,
		})
		if err != nil {
			fatalf("creating org: %v", err)
		}

		if jsonOutput {
			printJSON(org)
			return
		}

		fmt.Printf("Organization created: %s (%s)\n", org.Slug, org.Name)

	case "get":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: seki-cli org get SLUG")
			os.Exit(1)
		}

		org, err := c.GetOrg(ctx, rest[0])
		if err != nil {
			fatalf("getting org: %v", err)
		}

		if jsonOutput {
			printJSON(org)
			return
		}

		w := tableWriter()
		fmt.Fprintln(w, "ID\tSLUG\tNAME\tDOMAINS\tCREATED")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", org.ID, org.Slug, org.Name, strings.Join(org.Domains, ","), org.CreatedAt.Format("2006-01-02"))
		w.Flush()

	case "delete":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: seki-cli org delete SLUG")
			os.Exit(1)
		}

		if err := c.DeleteOrg(ctx, rest[0]); err != nil {
			fatalf("deleting org: %v", err)
		}

		fmt.Printf("Organization deleted: %s\n", rest[0])

	default:
		fmt.Fprintf(os.Stderr, "unknown org subcommand: %s\n", sub)
		os.Exit(1)
	}
}

// runClient handles OIDC client subcommands.
// Client management is done via seki.yaml configuration, not the Admin API.
func runClient(args []string) {
	fmt.Fprintln(os.Stderr, "OIDC client management is configured via seki.yaml.")
	fmt.Fprintln(os.Stderr, "Edit the 'clients' section in your configuration file to add, update, or remove clients.")
	fmt.Fprintln(os.Stderr, "Changes take effect on server restart.")
}

// runAudit handles audit log subcommands.
func runAudit(args []string, apiURL, apiKey string, jsonOutput bool) {
	if len(args) == 0 || args[0] != "list" {
		fmt.Fprintln(os.Stderr, "usage: seki-cli audit list [options]")
		os.Exit(1)
	}

	rest := args[1:]
	fs := flag.NewFlagSet("audit list", flag.ExitOnError)
	actor := fs.String("actor", "", "filter by actor ID")
	action := fs.String("action", "", "filter by action")
	limit := fs.Int("limit", 20, "max number of results")
	fs.Parse(rest)

	c := client.New(apiURL, apiKey)
	ctx := context.Background()

	result, err := c.ListAuditLogs(ctx, client.AuditListOptions{
		ActorID: *actor,
		Action:  *action,
		Limit:   *limit,
	})
	if err != nil {
		fatalf("listing audit logs: %v", err)
	}

	if jsonOutput {
		printJSON(result.Data)
		return
	}

	w := tableWriter()
	fmt.Fprintln(w, "ID\tACTOR\tACTION\tRESOURCE\tRESOURCE_ID\tTIME")
	for _, e := range result.Data {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.ActorID, e.Action, e.Resource, e.ResourceID, e.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	w.Flush()
}

// runMigrate runs database migrations.
// This requires direct database access via the server configuration.
func runMigrate(args []string) {
	fmt.Fprintln(os.Stderr, "Database migrations are run automatically when the seki server starts.")
	fmt.Fprintln(os.Stderr, "To run migrations manually, start the server: seki --config seki.yaml")
}
