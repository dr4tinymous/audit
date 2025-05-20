package audit

import (
	"context"
	"sync"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
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

type memSpill struct {
    mu     sync.Mutex
    events []Event
}

func (m *memSpill) Write(evt Event) error {
    m.mu.Lock()
    m.events = append(m.events, evt)
    m.mu.Unlock()
    return nil
}

// Close is required so memSpill satisfies SpillHandler.
func (m *memSpill) Close() error {
    // nothing to clean up in memory
    return nil
}

// Events returns a snapshot of spilled events.
func (m *memSpill) Events() []Event {
    m.mu.Lock()
    defer m.mu.Unlock()
    out := make([]Event, len(m.events))
    copy(out, m.events)
    return out
}

// Clear resets the in-memory spill log.
func (m *memSpill) Clear() {
    m.mu.Lock()
    m.events = nil
    m.mu.Unlock()
}

func TestSpillAndRecoverInMemory(t *testing.T) {
    cases := []struct {
        name         string
        opts         []BusOption
        handlerDelay time.Duration
        total        int
        wantSpilled  int
    }{
        {
            name: "queue overflow",
            opts: []BusOption{
                WithBufferSize(1),
                WithRateLimit(1000, 1000),
                WithAsync(true),
                WithWorkerCount(1),
            },
            handlerDelay: 50 * time.Millisecond,
            total:        10,
            wantSpilled:  6,
        },
        {
            name: "rate limit",
            opts: []BusOption{
                WithBufferSize(10),
                WithRateLimit(2, 2),
                WithAsync(true),
                WithWorkerCount(4),
            },
            handlerDelay: 0,
            total:        5,
            wantSpilled:  3,
        },
    }

    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            // inject our in-memory handler
            mem := &memSpill{}
            allOpts := append(c.opts, WithSpilloverHandler(mem))
            bus, err := NewBus(allOpts...)
            if err != nil {
                t.Fatalf("NewBus failed: %v", err)
            }
            defer bus.Close()

            // capture processed IDs
            var mu sync.Mutex
            processed := make([]string, 0, c.total)
            bus.Subscribe(EventType("test_event"), func(evt Event) error {
                if c.handlerDelay > 0 {
                    time.Sleep(c.handlerDelay)
                }
                mu.Lock()
                processed = append(processed, evt.ID())
                mu.Unlock()
                return nil
            })

            // publish all
            for i := 0; i < c.total; i++ {
                bus.Publish(NewBasicEvent("test_event", "src", "ctx",
                    map[string]interface{}{"i": i}, trace.SpanContext{}))
            }

            // let spill + dispatch settle
            time.Sleep(200 * time.Millisecond)

            // 1) check how many spilled in-memory
            spilled := mem.Events()
            if len(spilled) < c.wantSpilled {
                t.Fatalf("spilled = %d, want ≥%d", len(spilled), c.wantSpilled)
            }

            // 2) clear and replay them synchronously
            mem.Clear()
            for _, evt := range spilled {
                bus.PublishSync(evt)
            }
            time.Sleep(100 * time.Millisecond)

            // 3) verify total processed == total published
            mu.Lock()
            got := len(processed)
            mu.Unlock()
            if got != c.total {
                t.Errorf("processed = %d, want %d", got, c.total)
            }

            // 4) history must also contain all
            history, err := bus.History(adminCtx())
            if err != nil {
                t.Fatalf("History error: %v", err)
            }
            if len(history) != c.total {
                t.Errorf("history size = %d, want %d", len(history), c.total)
            }
        })
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

// Test that a panicking handler does not crash the Bus and
// allows subsequent handlers to run.
func TestHandlerPanicIsolation(t *testing.T) {
    ctx := adminCtx()
    bus, _ := NewBus(WithAsync(false), WithHistoryCap(2))
    defer bus.Close()

    var called bool
    bus.Subscribe(EventTypeCustomFieldSet, func(evt Event) error {
        panic("boom")
    })
    bus.Subscribe(EventTypeCustomFieldSet, func(evt Event) error {
        called = true
        return nil
    })

    evt := NewBasicEvent(EventTypeCustomFieldSet, "src", "", nil, trace.SpanContext{})
    bus.Publish(evt)

    history, _ := bus.History(ctx)
    if len(history) != 1 {
        t.Fatalf("expected history=1 after panic, got %d", len(history))
    }
    if !called {
        t.Error("second handler was not called after first panicked")
    }
}

// Test that events exceeding MaxMemoryMB are not stored.
func TestMemoryLimitEnforced(t *testing.T) {
    ctx := adminCtx()
    bus, _ := NewBus(WithMaxMemoryMB(1), WithHistoryCap(10), WithAsync(false))
    defer bus.Close()

    // payload ~2 MB
    large := strings.Repeat("x", 2*1024*1024)
    bus.Publish(NewBasicEvent("big", "src", "", map[string]interface{}{"data": large}, trace.SpanContext{}))

    history, _ := bus.History(ctx)
    if len(history) != 0 {
        t.Errorf("expected 0 events stored for >1MB payload, got %d", len(history))
    }
}

func TestConcurrentClose(t *testing.T) {
    bus, _ := NewBus(WithAsync(true))
    var wg sync.WaitGroup
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            bus.Close()
        }()
    }
    wg.Wait()
    // No panic expected
}