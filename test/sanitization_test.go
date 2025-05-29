package audit_test

import (
	"testing"

	"github.com/dr4tinymous/audit"
)

func TestSanitization(t *testing.T) {
	bus, _ := audit.NewBus()
	defer bus.Close()

	bus.Publish(audit.NewBasicEvent("test_event", "source", "ctx",
		map[string]interface{}{
			"email":    "user@example.com",
			"password": "secret",
			"data":     "visible",
		}, nil),
	)
	time.Sleep(20 * time.Millisecond)

	h, _ := bus.History(adminCtx())
	payload := h[0].Payload().(map[string]interface{})

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
