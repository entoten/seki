package storage_test

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/entoten/seki/internal/storage/sqlite"

	_ "modernc.org/sqlite"
)

func openMigrationDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatalf("pragma: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrationFilesHavePairs(t *testing.T) {
	migrations, err := sqlite.LoadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migration files found")
	}
	for _, m := range migrations {
		if m.UpSQL == "" {
			t.Errorf("migration %s: missing up SQL", m.Name)
		}
		if m.DownSQL == "" {
			t.Errorf("migration %s: missing down SQL", m.Name)
		}
	}
}

func TestMigrationVersionsSequential(t *testing.T) {
	migrations, err := sqlite.LoadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	for i, m := range migrations {
		expected := fmt.Sprintf("%03d", i+1)
		if m.Version != expected {
			t.Errorf("migration %d: want version %s, got %s", i, expected, m.Version)
		}
	}
}

func TestMigrateUp(t *testing.T) {
	db := openMigrationDB(t)
	if err := sqlite.RunMigrations(db); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	tables := []string{"users", "credentials", "clients", "sessions", "audit_logs"}
	for _, tbl := range tables {
		var name string
		err := db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", tbl, err)
		}
	}
}

func TestMigrateDown(t *testing.T) {
	db := openMigrationDB(t)
	if err := sqlite.RunMigrations(db); err != nil {
		t.Fatalf("up: %v", err)
	}
	if err := sqlite.RollbackAll(db); err != nil {
		t.Fatalf("down: %v", err)
	}
	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
	).Scan(&count)
	if err != nil {
		t.Fatalf("count tables: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 tables after rollback, got %d", count)
	}
}

func TestMigrateUpDownUp(t *testing.T) {
	db := openMigrationDB(t)
	if err := sqlite.RunMigrations(db); err != nil {
		t.Fatalf("first up: %v", err)
	}
	if err := sqlite.RollbackAll(db); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := sqlite.RunMigrations(db); err != nil {
		t.Fatalf("second up: %v", err)
	}
	var name string
	err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='users'",
	).Scan(&name)
	if err != nil {
		t.Fatalf("users table not found after re-migration: %v", err)
	}
}

func TestSessionTimeoutColumnsExist(t *testing.T) {
	db := openMigrationDB(t)
	if err := sqlite.RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	rows, err := db.Query("PRAGMA table_info(sessions)")
	if err != nil {
		t.Fatalf("pragma table_info: %v", err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt *string
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		columns[name] = true
	}
	required := []string{"last_active_at", "absolute_expires_at", "expires_at"}
	for _, col := range required {
		if !columns[col] {
			t.Errorf("sessions table missing column: %s", col)
		}
	}
}
