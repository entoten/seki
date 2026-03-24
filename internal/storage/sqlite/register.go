package sqlite

import (
	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
)

func init() {
	storage.Register("sqlite", func(cfg config.DatabaseConfig) (storage.Storage, error) {
		return New(cfg)
	})
}
