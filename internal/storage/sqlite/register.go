package sqlite

import "github.com/Monet/seki/internal/storage"

func init() {
	storage.Register("sqlite", func(dsn string) (storage.Storage, error) {
		return New(dsn)
	})
}
