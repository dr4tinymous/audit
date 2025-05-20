package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/trace"
)

func adminCtx() context.Context {
	return context.WithValue(context.Background(), "role", "admin")
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestCheckHistoryAccess(t *testing.T) {
	bus, err := NewBus(
		WithAccessControl(func(ctx context.Context) error {
			if role, ok := ctx.Value("role").(string); ok && role == "admin" {
				return nil
			}
			return fmt.Errorf("access denied")
		}),
	)
	if err != nil {
		t.Fatalf("Failed to create bus: %v", err)
	}
	defer bus.Close()

	if _, err := bus.History(adminCtx()); err != nil {
		t.Errorf("Expected no error for admin role, got: %v", err)
	}

	userCtx := context.WithValue(context.Background(), "role", "user")
	if _, err := bus.History(userCtx); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Errorf("Expected access denied error for non-admin, got: %v", err)
	}
}

func TestSetupDatabase(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	if err := SetupDatabase(db); err != nil {
		t.Fatalf("Failed to setup database: %v", err)
	}

	_, err = db.Exec(`INSERT INTO audit (id, type, time, source, context_id, payload)
		VALUES (?, ?, ?, ?, ?, ?)`,
		"test-id", "test_event", "2025-01-01T00:00:00Z", "test-source", "test-ctx", "{}")
	if err != nil {
		t.Fatalf("Failed to insert into audit table: %v", err)
	}

	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='audit'`)
	if err != nil {
		t.Fatalf("Failed to query indexes: %v", err)
	}
	defer rows.Close()

	indexes := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("Failed to scan index name: %v", err)
		}
		indexes[name] = true
	}
	if !indexes["idx_context_id"] || !indexes["idx_time"] {
		t.Error("Expected indexes idx_context_id and idx_time not found")
	}
}

func TestEncryptionKeyManagement(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key))
	}

	event := NewBasicEvent("test_event", "source", "ctx", map[string]interface{}{"data": "sensitive"}, trace.SpanContext{})
	encrypted, err := EncryptEvent(event, key)
	if err != nil {
		t.Fatalf("Failed to encrypt event: %v", err)
	}

	orig, _ := json.Marshal(event.Payload())
	enc, _ := json.Marshal(encrypted.Payload())
	if string(orig) != string(enc) {
		t.Errorf("Payload mismatch after encryption: %s vs %s", string(orig), string(enc))
	}
}

func TestSpilloverRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	bus, err := NewBus(
		WithSpilloverDir(tmpDir),
		WithBufferSize(1),
		WithHistoryCap(10),
	)
	if err != nil {
		t.Fatalf("Failed to create bus: %v", err)
	}
	defer bus.Close()

	for i := 0; i < 5; i++ {
		bus.Publish(NewBasicEvent("test_event", "source", "ctx", nil, trace.SpanContext{}))
	}
	time.Sleep(100 * time.Millisecond)

	if err := bus.RecoverSpillover(); err != nil {
		t.Fatalf("Failed to recover spillover: %v", err)
	}

	history, err := bus.History(adminCtx())
	if err != nil {
		t.Fatalf("Failed to get history: %v", err)
	}
	if len(history) == 0 {
		t.Error("Expected recovered events in history, got none")
	}

	info, _ := os.Stat(filepath.Join(tmpDir, "spillover.log"))
	if info.Size() != 0 {
		t.Error("Expected spillover file to be truncated after recovery")
	}
}

func TestNonLatinCharacters(t *testing.T) {
	bus, _ := NewBus()
	defer bus.Close()

	msg := "こんにちは, 世界! مرحبا"
	bus.Publish(NewBasicEvent("test_event", "source", "ctx", map[string]interface{}{"message": msg}, trace.SpanContext{}))

	history, err := bus.History(adminCtx())
	if err != nil {
		t.Fatalf("Failed to get history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(history))
	}
	if history[0].Payload().(map[string]interface{})["message"] != msg {
		t.Error("Non-Latin characters not preserved")
	}
}

func TestMetricsRegistration(t *testing.T) {
	reg1 := prometheus.NewRegistry()
	reg2 := prometheus.NewRegistry()

	bus1, _ := NewBus(WithMetrics(NewPrometheusMetrics(reg1)))
	defer bus1.Close()
	bus2, _ := NewBus(WithMetrics(NewPrometheusMetrics(reg2)))
	defer bus2.Close()

	evt := NewBasicEvent("test_event", "source", "ctx", nil, trace.SpanContext{})
	bus1.Publish(evt)
	bus2.Publish(evt)
	time.Sleep(100 * time.Millisecond)

	c1, _ := testutil.GatherAndCount(reg1, "audit_events_published_total")
	c2, _ := testutil.GatherAndCount(reg2, "audit_events_published_total")
	if c1 != 1 || c2 != 1 {
		t.Errorf("Expected 1 event per registry, got bus1=%d, bus2=%d", c1, c2)
	}
}

func TestRateLimiting(t *testing.T) {
	bus, _ := NewBus(
		WithBufferSize(10),
		WithRateLimit(2, 2),
		WithAsync(true),
		WithWorkerCount(1),
	)
	defer bus.Close()

	for i := 0; i < 5; i++ {
		bus.Publish(NewBasicEvent("test_event", "source", "ctx", nil, trace.SpanContext{}))
	}
	time.Sleep(500 * time.Millisecond)

	history, _ := bus.History(adminCtx())
	if len(history) >= 5 {
		t.Errorf("Expected some events to be dropped due to rate limiting, got %d", len(history))
	}
}


func TestCustomEvent(t *testing.T) {
	bus, _ := NewBus()
	defer bus.Close()

	typ := EventType("custom_event")
	RegisterSchema(typ, EventSchema{
		RequiredFields: []string{"action", "details"},
		FieldTypes: map[string]reflect.Type{
			"action":  reflect.TypeOf(""),
			"details": reflect.TypeOf(""),
		},
	})

	valid := NewBasicEvent(typ, "source", "ctx", map[string]interface{}{"action": "start", "details": "init"}, trace.SpanContext{})
	bus.Publish(valid)

	history, _ := bus.History(adminCtx())
	if len(history) != 1 {
		t.Fatalf("Expected 1 valid event, got %d", len(history))
	}

	invalid := NewBasicEvent(typ, "source", "ctx", map[string]interface{}{"action": "only"}, trace.SpanContext{})
	bus.Publish(invalid)
	time.Sleep(100 * time.Millisecond)

	history, _ = bus.History(adminCtx())
	if len(history) != 1 {
		t.Error("Invalid event should not be stored")
	}
}

func TestSanitization(t *testing.T) {
	bus, _ := NewBus()
	defer bus.Close()

	bus.Publish(NewBasicEvent("test_event", "source", "ctx", map[string]interface{}{
		"email":    "user@example.com",
		"password": "secret",
		"data":     "visible",
	}, trace.SpanContext{}))
	time.Sleep(100 * time.Millisecond)

	history, _ := bus.History(adminCtx())
	payload := history[0].Payload().(map[string]interface{})

	if payload["email"] != "u****@example.com" {
		t.Errorf("Email not sanitized: %v", payload["email"])
	}
	if payload["password"] != "****" {
		t.Errorf("Password not sanitized: %v", payload["password"])
	}
	if payload["data"] != "visible" {
		t.Errorf("Data incorrectly sanitized: %v", payload["data"])
	}
}
