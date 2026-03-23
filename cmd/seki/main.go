package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Monet/seki/internal/config"
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

	fmt.Printf("seki v%s\n", version)
	fmt.Printf("issuer:   %s\n", cfg.Server.Issuer)
	fmt.Printf("address:  %s\n", cfg.Server.Address)
	fmt.Printf("database: %s\n", cfg.Database.Driver)

	// TODO: Start HTTP server
	// srv := server.New(cfg)
	// srv.ListenAndServe()
}
