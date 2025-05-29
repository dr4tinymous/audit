package audit_test

import (
	"encoding/json"
	"testing"

	"go.opentelemetry.io/otel/trace"

	"github.com/dr4tinymous/audit"
)

func TestEncryptionKeyManagement(t *testing.T) {
	key, err := audit.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key))
	}

	evt := audit.NewBasicEvent("test_event", "source", "ctx",
		map[string]interface{}{"data": "sensitive"}, trace.SpanContext{},
	)
	encrypted, err := audit.EncryptEvent(evt, key)
	if err != nil {
		t.Fatalf("Failed to encrypt event: %v", err)
	}

	orig, _ := json.Marshal(evt.Payload())
	enc, _ := json.Marshal(encrypted.Payload())
	if string(orig) != string(enc) {
		t.Errorf("Payload mismatch after encryption: %s vs %s", string(orig), string(enc))
	}
}
