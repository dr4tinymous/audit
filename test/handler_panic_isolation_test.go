package audit_test

import (
	"testing"

	"github.com/dr4tinymous/audit"
)

func TestHandlerPanicIsolation(t *testing.T) {
	bus, _ := audit.NewBus(audit.WithAsync(false), audit.WithHistoryCap(2))
	defer bus.Close()

	var called bool
	bus.Subscribe(audit.EventTypeCustomFieldSet, func(evt audit.Event) error {
		panic("boom")
	})
	bus.Subscribe(audit.EventTypeCustomFieldSet, func(evt audit.Event) error {
		called = true
		return nil
	})

	evt := audit.NewBasicEvent(audit.EventTypeCustomFieldSet, "src", "", nil, nil)
	bus.Publish(evt)

	h, _ := bus.History(adminCtx())
	if len(h) != 1 {
		t.Fatalf("expected history=1 after panic, got %d", len(h))
	}
	if !called {
		t.Error("second handler was not called after first panicked")
	}
}
