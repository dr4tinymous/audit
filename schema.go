package audit

import (
	"fmt"
	"reflect"
	"sync"
)

// EventSchema defines the validation rules for audit event payloads.
// Used to enforce structural and typal constraints on event data.
//
// Fields:
//   - RequiredFields: List of mandatory field names that must exist in payload
//   - FieldTypes: Type constraints for specific fields (nil values allow any type)
//
// Example:
//  audit.RegisterSchema("user.login", EventSchema{
//      RequiredFields: []string{"user_id", "timestamp"},
//      FieldTypes: map[string]reflect.Type{
//          "user_id":   reflect.TypeOf(""),
//          "timestamp": reflect.TypeOf(time.Time{}),
//      },
//  })
type EventSchema struct {
	RequiredFields []string
	FieldTypes     map[string]reflect.Type
}

// schemaRegistry maintains a global registry of event type to schema mappings.
// Protected by schemaMu for concurrent access. Accessed via RegisterSchema and
// validatePayload functions.
var (
	schemaRegistry = make(map[EventType]EventSchema)
	schemaMu       sync.RWMutex
)

// RegisterSchema adds or updates a schema definition for a specific event type.
// Thread-safe: safe for concurrent use via mutex synchronization.
//
// Parameters:
//   - et: EventType to associate with the schema
//   - s:  EventSchema containing validation rules
//
// Note: Subsequent registrations for the same EventType overwrite previous schemas.
func RegisterSchema(et EventType, s EventSchema) {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	schemaRegistry[et] = s
}

// validatePayload ensures an event's payload conforms to its registered schema.
// Performs the following checks when a schema exists for the event type:
//   1. Verifies presence of all RequiredFields
//   2. Validates field types match FieldTypes (when specified)
//   3. Ensures payload is a map[string]interface{} when schema exists
//
// Nil payloads are considered valid and skip validation.
//
// Returns:
//   - error: Descriptive validation error detailing schema violations
//   - nil:   When payload passes validation or no schema is registered
func validatePayload(evt Event) error {
	// Allow nil payloads to pass validation (explicit empty payload)
	if evt.Payload() == nil {
		return nil
	}
	
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
	
	// Validate required fields
	for _, key := range s.RequiredFields {
		if _, exists := pl[key]; !exists {
			return fmt.Errorf("schema violation for %s: missing required field %s", evt.Type(), key)
		}
		// Validate field type if constraint exists
		if expectedType, ok := s.FieldTypes[key]; ok && expectedType != nil {
			if actual := reflect.TypeOf(pl[key]); actual != expectedType {
				return fmt.Errorf("schema violation for %s: field %s has wrong type, expected %v, got %v", 
					evt.Type(), key, expectedType, actual)
			}
		}
	}
	
	return nil
}