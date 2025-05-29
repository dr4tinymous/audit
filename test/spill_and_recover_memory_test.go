package audit_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dr4tinymous/audit"
)

type memSpill struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memSpill) Write(evt audit.Event) error {
	m.mu.Lock()
	m.events = append(m.events, evt)
	m.mu.Unlock()
	return nil
}

func (m *memSpill) Close() error { return nil }

func (m *memSpill) Events() []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]audit.Event, len(m.events))
	copy(out, m.events)
	return out
}

func (m *memSpill) Clear() {
	m.mu.Lock()
	m.events = nil
	m.mu.Unlock()
}

func TestSpillAndRecoverInMemory(t *testing.T) {
	cases := []struct {
		name         string
		opts         []audit.BusOption
		handlerDelay time.Duration
		total        int
		wantSpilled  int
	}{
		{
			name: "queue overflow",
			opts: []audit.BusOption{
				audit.WithBufferSize(1),
				audit.WithRateLimit(1000, 1000),
				audit.WithAsync(true),
				audit.WithWorkerCount(1),
			},
			handlerDelay: 50 * time.Millisecond,
			total:        10,
			wantSpilled:  6,
		},
		{
			name: "rate limit",
			opts: []audit.BusOption{
				audit.WithBufferSize(10),
				audit.WithRateLimit(2, 2),
				audit.WithAsync(true),
				audit.WithWorkerCount(4),
			},
			handlerDelay: 0,
			total:        5,
			wantSpilled:  3,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mem := &memSpill{}
			opts := append(c.opts, audit.WithSpilloverHandler(mem))
			bus, err := audit.NewBus(opts...)
			if err != nil {
				t.Fatalf("audit.NewBus failed: %v", err)
			}
			defer bus.Close()

			var mu sync.Mutex
			processed := make([]string, 0, c.total)
			bus.Subscribe(audit.EventType("test_event"), func(evt audit.Event) error {
				if c.handlerDelay > 0 {
					time.Sleep(c.handlerDelay)
				}
				mu.Lock()
				processed = append(processed, evt.ID())
				mu.Unlock()
				return nil
			})

			for i := 0; i < c.total; i++ {
				bus.Publish(audit.NewBasicEvent("test_event", "src", "ctx",
					map[string]interface{}{"i": i}, nil))
			}
			time.Sleep(200 * time.Millisecond)

			spilled := mem.Events()
			if len(spilled) < c.wantSpilled {
				t.Fatalf("spilled = %d, want ≥%d", len(spilled), c.wantSpilled)
			}

			mem.Clear()
			for _, evt := range spilled {
				bus.PublishSync(evt)
			}
			time.Sleep(50 * time.Millisecond)

			mu.Lock()
			got := len(processed)
			mu.Unlock()
			if got != c.total {
				t.Errorf("processed = %d, want %d", got, c.total)
			}

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
