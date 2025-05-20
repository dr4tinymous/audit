package audit

import (
	"fmt"
	"reflect"
	"sync"
)

// EventSchema defines the schema for an event's payload.
type EventSchema struct {
	RequiredFields []string
	FieldTypes     map[string]reflect.Type
}

// schemaRegistry holds event type schemas.
var (
	schemaRegistry = make(map[EventType]EventSchema)
	schemaMu       sync.RWMutex
)

// RegisterSchema registers a schema for an event type.
func RegisterSchema(et EventType, s EventSchema) {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	schemaRegistry[et] = s
}

// validatePayload checks if the payload matches the registered schema.
func validatePayload(evt Event) error {
	schemaMu.RLock()
	s, ok := schemaRegistry[evt.Type()]
	schemaMu.RUnlock()
	if !ok {
		return nil
	}
	pl, ok := evt.Payload().(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid payload type for %s: expected map[string]interface{}", evt.Type())
	}
	for _, key := range s.RequiredFields {
		if _, exists := pl[key]; !exists {
			return fmt.Errorf("schema violation for %s: missing required field %s", evt.Type(), key)
		}
		if expectedType, ok := s.FieldTypes[key]; ok && expectedType != nil {
			if actual := reflect.TypeOf(pl[key]); actual != expectedType {
				return fmt.Errorf("schema violation for %s: field %s has wrong type, expected %v, got %v", evt.Type(), key, expectedType, actual)
			}
		}
	}
	return nil
}