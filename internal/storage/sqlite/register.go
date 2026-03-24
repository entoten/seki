package sqlite

import (
	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/storage"
)

func init() {
	storage.Register("sqlite", func(cfg config.DatabaseConfig) (storage.Storage, error) {
		return New(cfg)
	})
}
