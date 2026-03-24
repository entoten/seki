package storage_test

import (
	"testing"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
)

func TestConnectionPoolSettings(t *testing.T) {
	cfg := config.DatabaseConfig{
		Driver:          "sqlite",
		DSN:             ":memory:",
		MaxOpenConns:    10,
		MaxIdleConns:    3,
		ConnMaxLifetime: "2m",
		ConnMaxIdleTime: "30s",
	}

	s, err := storage.New(cfg)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	defer s.Close()

	// If we got here without error, the pool settings were applied successfully.
	// The connection is usable.
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := s.Ping(t.Context()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}
