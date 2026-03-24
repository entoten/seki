package storage_test

import (
	"testing"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/storage"
)

func TestNew_UnknownDriver(t *testing.T) {
	_, err := storage.New(config.DatabaseConfig{
		Driver: "nonexistent-driver",
		DSN:    ":memory:",
	})
	if err == nil {
		t.Fatal("expected error for unknown driver")
	}
}
