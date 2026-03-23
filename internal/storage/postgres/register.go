package postgres

import (
	"context"

	"github.com/Monet/seki/internal/storage"
)

func init() {
	storage.Register("postgres", func(dsn string) (storage.Storage, error) {
		return New(context.Background(), dsn)
	})
}
