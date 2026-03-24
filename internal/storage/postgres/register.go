package postgres

import (
	"context"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/storage"
)

func init() {
	storage.Register("postgres", func(cfg config.DatabaseConfig) (storage.Storage, error) {
		return New(context.Background(), cfg)
	})
}
