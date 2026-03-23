package storage

import (
	"fmt"

	"github.com/Monet/seki/internal/config"
)

// NewFunc is the type for driver-specific constructor functions.
// Drivers register themselves so the factory can remain decoupled.
type NewFunc func(dsn string) (Storage, error)

var drivers = map[string]NewFunc{}

// Register registers a storage driver constructor under the given name.
func Register(name string, fn NewFunc) {
	drivers[name] = fn
}

// New creates a Storage implementation based on the config driver name.
func New(cfg config.DatabaseConfig) (Storage, error) {
	fn, ok := drivers[cfg.Driver]
	if !ok {
		return nil, fmt.Errorf("storage: unknown driver %q (registered: %v)", cfg.Driver, driverNames())
	}
	return fn(cfg.DSN)
}

func driverNames() []string {
	names := make([]string, 0, len(drivers))
	for k := range drivers {
		names = append(names, k)
	}
	return names
}
