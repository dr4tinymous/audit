package audit_test

import (
	"testing"

	"github.com/dr4tinymous/audit"
)

func TestNonLatinCharacters(t *testing.T) {
	bus, _ := audit.NewBus()
	defer bus.Close()

	msg := "こんにちは, 世界! مرحبا"
	bus.Publish(audit.NewBasicEvent("test_event", "source", "ctx",
		map[string]interface{}{"message": msg}, nil),
	)

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
