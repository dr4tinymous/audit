package audit_test

import (
	"reflect"
	"testing"

	"github.com/dr4tinymous/audit"
)

func TestCustomEvent(t *testing.T) {
	bus, _ := audit.NewBus()
	defer bus.Close()

	typ := audit.EventType("custom_event")
	audit.RegisterSchema(typ, audit.EventSchema{
		RequiredFields: []string{"action", "details"},
		FieldTypes: map[string]reflect.Type{
			"action":  reflect.TypeOf(""),
			"details": reflect.TypeOf(""),
		},
	})

	valid := audit.NewBasicEvent(typ, "source", "ctx",
		map[string]interface{}{"action": "start", "details": "init"}, nil,
	)
	bus.Publish(valid)

	h, _ := bus.History(adminCtx())
	if len(h) != 1 {
		t.Fatalf("Expected 1 valid event, got %d", len(h))
	}

	invalid := audit.NewBasicEvent(typ, "source", "ctx",
		map[string]interface{}{"action": "only"}, nil,
	)
	bus.Publish(invalid)

	h, _ = bus.History(adminCtx())
	if len(h) != 1 {
		t.Error("Invalid event should not be stored")
	}
}
