package audit_test

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/dr4tinymous/audit"
)

func TestSetupDatabase(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	if err := audit.SetupDatabase(db); err != nil {
		t.Fatalf("Failed to setup database: %v", err)
	}

	// Insert a row to verify schema
	_, err = db.Exec(
		`INSERT INTO audit (id, type, time, source, context_id, payload) VALUES (?, ?, ?, ?, ?, ?)`,
		"test-id", "test_event", "2025-01-01T00:00:00Z", "test-source", "test-ctx", "{}",
	)
	if err != nil {
		t.Fatalf("Failed to insert row: %v", err)
	}

	// Check indexes
	rows, err := db.Query(
		`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='audit'`,
	)
	if err != nil {
		t.Fatalf("Failed to query indexes: %v", err)
	}
	defer rows.Close()

	found := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("Failed to scan index name: %v", err)
		}
		found[name] = true
	}
	if !found["idx_context_id"] || !found["idx_time"] {
		t.Error("Expected indexes idx_context_id and idx_time not found")
	}
}
