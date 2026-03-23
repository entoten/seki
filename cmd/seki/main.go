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

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/crypto"
	"github.com/Monet/seki/internal/server"
	"github.com/Monet/seki/internal/storage"
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

	if err := store.Migrate(); err != nil {
		fmt.Fprintf(os.Stderr, "error running migrations: %v\n", err)
		os.Exit(1)
	}

	srv := server.New(cfg, store, signer)

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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
		os.Exit(1)
	}

	log.Printf("server stopped")
}
