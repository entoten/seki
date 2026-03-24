package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/entoten/seki/internal/admin"
	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/logging"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/server"
	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/telemetry"
	_ "github.com/entoten/seki/internal/storage/postgres"
	_ "github.com/entoten/seki/internal/storage/sqlite"
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

	// Set up structured logging.
	logger := logging.Setup(cfg.Log.Level, cfg.Log.Format)

	// Set up OpenTelemetry tracing.
	telemetryShutdown, err := telemetry.Setup(cfg.Telemetry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "telemetry setup error: %v\n", err)
		os.Exit(1)
	}
	defer telemetryShutdown(context.Background())

	// Print startup banner.
	printBanner(cfg)

	// Initialize the token signer.
	signer, err := crypto.NewEd25519Signer(crypto.Ed25519SignerOptions{
		KeyFile: cfg.Signing.KeyFile,
		Issuer:  cfg.Server.Issuer,
	})
	if err != nil {
		logger.Error("failed to initialize signer", "error", err)
		os.Exit(1)
	}

	// Initialize the storage layer.
	store, err := storage.New(cfg.Database)
	if err != nil {
		logger.Error("failed to initialize storage", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	// Run database migrations.
	if err := store.Migrate(); err != nil {
		logger.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Seed OIDC clients from config.
	ctx := context.Background()
	if len(cfg.Clients) > 0 {
		if err := oidc.SeedClientsFromConfig(ctx, store, cfg.Clients); err != nil {
			logger.Warn("failed to seed clients", "error", err)
		} else {
			logger.Info("seeded clients from config", "count", len(cfg.Clients))
		}
	}

	// Seed organizations from config.
	if len(cfg.Organizations) > 0 {
		if err := admin.SeedOrgsFromConfig(ctx, store, cfg.Organizations); err != nil {
			logger.Warn("failed to seed organizations", "error", err)
		} else {
			logger.Info("seeded organizations from config", "count", len(cfg.Organizations))
		}
	}

	// Create the server (wires session manager, audit logger, webhook emitter,
	// OIDC provider, admin handler, and authn routes internally).
	srv := server.New(cfg, store, signer)

	// Start server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		logger.Info("server listening", "address", cfg.Server.Address)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Listen for SIGINT/SIGTERM (shutdown) and SIGHUP (config reload).
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case sig := <-quit:
			if sig == syscall.SIGHUP {
				handleReload(*configPath, cfg, srv, logger)
				continue
			}
			logger.Info("received shutdown signal", "signal", sig.String())
			goto shutdown
		case err := <-errCh:
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}

shutdown:
	// Graceful shutdown with timeout.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}

// handleReload re-reads the config file and applies hot-reloadable settings.
func handleReload(configPath string, current *config.Config, srv *server.Server, logger *slog.Logger) {
	logger.Info("SIGHUP received, reloading configuration", "path", configPath)

	newCfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("config reload failed", "error", err)
		return
	}

	var reloaded []string

	// Hot-reload log level.
	if newCfg.Log.Level != current.Log.Level {
		logging.SetLevel(newCfg.Log.Level)
		logger.Info("log level updated", "old", current.Log.Level, "new", newCfg.Log.Level)
		current.Log.Level = newCfg.Log.Level
		reloaded = append(reloaded, "log.level")
	}

	// Hot-reload rate limit thresholds.
	if newCfg.RateLimit.RequestsPerMin != current.RateLimit.RequestsPerMin ||
		newCfg.RateLimit.LoginAttemptsMax != current.RateLimit.LoginAttemptsMax ||
		newCfg.RateLimit.LockoutDuration != current.RateLimit.LockoutDuration ||
		newCfg.RateLimit.Enabled != current.RateLimit.Enabled {
		current.RateLimit = newCfg.RateLimit
		reloaded = append(reloaded, "rate_limit")
		logger.Info("rate limit config updated",
			"enabled", newCfg.RateLimit.Enabled,
			"requests_per_min", newCfg.RateLimit.RequestsPerMin,
			"login_attempts_max", newCfg.RateLimit.LoginAttemptsMax,
		)
	}

	if len(reloaded) == 0 {
		logger.Info("config reload complete, no hot-reloadable changes detected")
	} else {
		logger.Info("config reload complete", "reloaded", reloaded)
	}
}

// printBanner prints a human-readable startup summary.
func printBanner(cfg *config.Config) {
	var authMethods []string
	if cfg.Authentication.Passkey.Enabled {
		authMethods = append(authMethods, "passkey")
	}
	if cfg.Authentication.TOTP.Enabled {
		authMethods = append(authMethods, "totp")
	}
	if cfg.Authentication.Password.Enabled {
		authMethods = append(authMethods, "password")
	}
	if len(cfg.Authentication.Social) > 0 {
		providers := make([]string, 0, len(cfg.Authentication.Social))
		for name := range cfg.Authentication.Social {
			providers = append(providers, name)
		}
		sort.Strings(providers)
		authMethods = append(authMethods, providers...)
	}
	authStr := "none"
	if len(authMethods) > 0 {
		authStr = strings.Join(authMethods, ", ")
	}

	adminStatus := "disabled"
	if len(cfg.Admin.APIKeys) > 0 {
		adminStatus = fmt.Sprintf("enabled (%d key configured)", len(cfg.Admin.APIKeys))
		if len(cfg.Admin.APIKeys) > 1 {
			adminStatus = fmt.Sprintf("enabled (%d keys configured)", len(cfg.Admin.APIKeys))
		}
	}

	scimStatus := "disabled"
	if len(cfg.Admin.APIKeys) > 0 {
		scimStatus = "enabled"
	}

	fmt.Printf("seki v%s\n", version)
	fmt.Printf("  Issuer:     %s\n", cfg.Server.Issuer)
	fmt.Printf("  Database:   %s\n", cfg.Database.Driver)
	fmt.Printf("  Listening:  %s\n", cfg.Server.Address)
	fmt.Printf("  Auth:       %s\n", authStr)
	fmt.Printf("  Admin API:  %s\n", adminStatus)
	fmt.Printf("  SCIM:       %s\n", scimStatus)
	fmt.Printf("  Metrics:    /metrics\n")
}
