package audit

import (
	"context"
	"encoding/json"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// AccessControlFunc defines a function to check history access permissions.
type AccessControlFunc func(ctx context.Context) error

// Sanitizer defines a function to sanitize sensitive data.
type Sanitizer func(key string, value interface{}) interface{}

// defaultSanitizers holds default sanitization rules.
var defaultSanitizers = map[string]Sanitizer{
	"email": func(key string, value interface{}) interface{} {
		if v, ok := value.(string); ok {
			parts := strings.Split(v, "@")
			if len(parts) == 2 {
				return parts[0][:1] + "****@" + parts[1]
			}
		}
		return value
	},
	"password": func(key string, value interface{}) interface{} {
		return "****"
	},
}

// GenerateAESKey generates a 32-byte AES key for encryption.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return key, nil
}

// SanitizePayload sanitizes sensitive fields in an event's payload.
func SanitizePayload(evt Event) Event {
	payload, ok := evt.Payload().(map[string]interface{})
	if !ok {
		return evt
	}
	newPayload := make(map[string]interface{})
	for k, v := range payload {
		if sanitizer, exists := defaultSanitizers[k]; exists {
			newPayload[k] = sanitizer(k, v)
		} else {
			newPayload[k] = v
		}
	}
	return &sanitizedEvent{Event: evt, payload: newPayload}
}

// sanitizedEvent wraps an event with a sanitized payload.
type sanitizedEvent struct {
	Event
	payload interface{}
}

func (e *sanitizedEvent) Payload() interface{} { return e.payload }

// EncryptEvent encrypts an event's payload using AES.
func EncryptEvent(evt Event, key []byte) (Event, error) {
	data, err := json.Marshal(evt.Payload())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return &encryptedEvent{
		Event:      evt,
		encrypted:  base64.StdEncoding.EncodeToString(ciphertext),
		original:   evt.Payload(),
	}, nil
}

// encryptedEvent wraps an event with an encrypted payload.
type encryptedEvent struct {
	Event
	encrypted string
	original  interface{}
}

func (e *encryptedEvent) Payload() interface{} { return e.original }

// CheckHistoryAccess verifies access to history data.
func CheckHistoryAccess(ctx context.Context) error {
	if val := ctx.Value(accessControlKey{}); val != nil {
		if accessFunc, ok := val.(AccessControlFunc); ok && accessFunc != nil {
			return accessFunc(ctx)
		}
	}
	role, _ := ctx.Value("role").(string)
	if role != "admin" {
		return fmt.Errorf("access denied: insufficient permissions")
	}
	return nil
}


// accessControlKey is used to store the access control function in context.
type accessControlKey struct{}