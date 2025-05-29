package audit_test

import (
	"strings"
	"testing"

	"github.com/dr4tinymous/audit"
)

func TestMemoryLimitEnforced(t *testing.T) {
	bus, _ := audit.NewBus(audit.WithMaxMemoryMB(1), audit.WithHistoryCap(10), audit.WithAsync(false))
	defer bus.Close()

	large := strings.Repeat("x", 2*1024*1024)
	bus.Publish(audit.NewBasicEvent("big", "src", "", map[string]interface{}{"data": large}, nil))

	h, _ := bus.History(adminCtx())
	if len(h) != 0 {
		t.Errorf("expected 0 events stored for >1MB payload, got %d", len(h))
	}
}
