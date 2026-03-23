package main

import (
	"fmt"
	"os"
)

var version = "0.1.0-dev"

func main() {
	fmt.Printf("seki v%s\n", version)

	// TODO: Load configuration
	// cfg, err := config.Load()

	// TODO: Start HTTP server
	// srv := server.New(cfg)
	// srv.ListenAndServe()

	os.Exit(0)
}
