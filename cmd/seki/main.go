package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Monet/seki/internal/admin"
	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/crypto"
	"github.com/Monet/seki/internal/oidc"
	"github.com/Monet/seki/internal/server"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/postgres"
	_ "github.com/Monet/seki/internal/storage/sqlite"
)

var version = "0.1.0-dev"

func main() {
	configPath := flag.String("config", config.DefaultPath, "path to seki.yaml config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("seki v%s\n", version)
		os.Exit(0)
	}

	// Allow SEKI_CONFIG env var to override the default, but flag takes priority.
	if *configPath == config.DefaultPath {
		if envPath := os.Getenv("SEKI_CONFIG"); envPath != "" {
			*configPath = envPath
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	log.Printf("seki v%s starting", version)
	log.Printf("issuer:   %s", cfg.Server.Issuer)
	log.Printf("address:  %s", cfg.Server.Address)
	log.Printf("database: %s", cfg.Database.Driver)

	// Initialize the token signer.
	signer, err := crypto.NewEd25519Signer(crypto.Ed25519SignerOptions{
		KeyFile: cfg.Signing.KeyFile,
		Issuer:  cfg.Server.Issuer,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing signer: %v\n", err)
		os.Exit(1)
	}

	// Initialize the storage layer.
	store, err := storage.New(cfg.Database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing storage: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	// Run database migrations.
	if err := store.Migrate(); err != nil {
		fmt.Fprintf(os.Stderr, "error running migrations: %v\n", err)
		os.Exit(1)
	}

	// Seed OIDC clients from config.
	ctx := context.Background()
	if len(cfg.Clients) > 0 {
		if err := oidc.SeedClientsFromConfig(ctx, store, cfg.Clients); err != nil {
			log.Printf("warning: failed to seed clients: %v", err)
		} else {
			log.Printf("seeded %d client(s) from config", len(cfg.Clients))
		}
	}

	// Seed organizations from config.
	if len(cfg.Organizations) > 0 {
		if err := admin.SeedOrgsFromConfig(ctx, store, cfg.Organizations); err != nil {
			log.Printf("warning: failed to seed organizations: %v", err)
		} else {
			log.Printf("seeded %d organization(s) from config", len(cfg.Organizations))
		}
	}

	// Create the server (wires session manager, audit logger, webhook emitter,
	// OIDC provider, admin handler, and authn routes internally).
	srv := server.New(cfg, store, signer)

	log.Printf("audit output: %s", cfg.Audit.Output)
	if len(cfg.Webhooks.Endpoints) > 0 {
		log.Printf("webhook endpoints: %d", len(cfg.Webhooks.Endpoints))
	}
	if len(cfg.Admin.APIKeys) > 0 {
		log.Printf("admin API keys configured: %d", len(cfg.Admin.APIKeys))
	}

	// Log authentication methods.
	if cfg.Authentication.Passkey.Enabled {
		log.Printf("authn: passkey enabled (rp_id=%s)", cfg.Authentication.Passkey.RPID)
	}
	if cfg.Authentication.TOTP.Enabled {
		log.Printf("authn: totp enabled")
	}
	if cfg.Authentication.Password.Enabled {
		log.Printf("authn: password enabled")
	}
	if len(cfg.Authentication.Social) > 0 {
		for name := range cfg.Authentication.Social {
			log.Printf("authn: social provider %q configured", name)
		}
	}

	// Start server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", cfg.Server.Address)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for interrupt signal or server error.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Printf("received signal %s, shutting down", sig)
	case err := <-errCh:
		log.Printf("server error: %v", err)
		os.Exit(1)
	}

	// Graceful shutdown with timeout.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
		os.Exit(1)
	}

	log.Printf("server stopped")
}
