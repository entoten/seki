package storage

import "github.com/entoten/seki/internal/config"

// TestDatabaseConfig returns a DatabaseConfig pointing to an in-memory SQLite database.
// Intended for use in tests only.
func TestDatabaseConfig() config.DatabaseConfig {
	return config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    ":memory:",
	}
}
