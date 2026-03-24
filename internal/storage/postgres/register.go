package postgres

import (
	"context"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
)

func init() {
	storage.Register("postgres", func(cfg config.DatabaseConfig) (storage.Storage, error) {
		return New(context.Background(), cfg)
	})
}
