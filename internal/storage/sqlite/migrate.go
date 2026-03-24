package sqlite

import (
	"database/sql"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// MigrationEntry represents a single numbered migration with up and down SQL.
type MigrationEntry struct {
	Version string // e.g. "001"
	Name    string // e.g. "001_init"
	UpSQL   string
	DownSQL string
}

// LoadMigrations reads all migration pairs from the embedded filesystem.
// It returns them sorted by version ascending.
func LoadMigrations() ([]MigrationEntry, error) {
	return loadMigrationsFrom(migrationsFS, "migrations")
}

func loadMigrationsFrom(fsys fs.FS, dir string) ([]MigrationEntry, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	// Group files by version prefix.
	upFiles := map[string]string{}   // version -> filename
	downFiles := map[string]string{} // version -> filename

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".up.sql") {
			base := strings.TrimSuffix(name, ".up.sql")
			ver := strings.SplitN(base, "_", 2)[0]
			upFiles[ver] = name
		} else if strings.HasSuffix(name, ".down.sql") {
			base := strings.TrimSuffix(name, ".down.sql")
			ver := strings.SplitN(base, "_", 2)[0]
			downFiles[ver] = name
		}
	}

	// Build sorted list.
	versions := make([]string, 0, len(upFiles))
	for v := range upFiles {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	migrations := make([]MigrationEntry, 0, len(versions))
	for _, ver := range versions {
		upFile := upFiles[ver]
		downFile, hasDown := downFiles[ver]

		upData, err := fs.ReadFile(fsys, path.Join(dir, upFile))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", upFile, err)
		}

		var downData []byte
		if hasDown {
			downData, err = fs.ReadFile(fsys, path.Join(dir, downFile))
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", downFile, err)
			}
		}

		baseName := strings.TrimSuffix(upFile, ".up.sql")
		migrations = append(migrations, MigrationEntry{
			Version: ver,
			Name:    baseName,
			UpSQL:   string(upData),
			DownSQL: string(downData),
		})
	}

	return migrations, nil
}

// RunMigrations applies all up migrations in order.
func RunMigrations(db *sql.DB) error {
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if _, err := db.Exec(m.UpSQL); err != nil {
			return fmt.Errorf("migration %s up: %w", m.Name, err)
		}
	}
	return nil
}

// RollbackAll applies all down migrations in reverse order.
func RollbackAll(db *sql.DB) error {
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}
	// Apply in reverse.
	for i := len(migrations) - 1; i >= 0; i-- {
		m := migrations[i]
		if m.DownSQL == "" {
			return fmt.Errorf("migration %s has no down SQL", m.Name)
		}
		if _, err := db.Exec(m.DownSQL); err != nil {
			return fmt.Errorf("migration %s down: %w", m.Name, err)
		}
	}
	return nil
}

// DB returns the underlying *sql.DB for testing purposes.
func (s *Store) DB() *sql.DB {
	return s.db
}
