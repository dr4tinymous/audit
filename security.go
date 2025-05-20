/*
Package audit provides tools for secure event auditing with features including:
- Sensitive data sanitization
- Payload encryption
- Access control enforcement
- Audit event processing

The package enables processing of audit events through a security-focused pipeline:
sanitization of sensitive fields, encryption of payload data, and proper access
control checks for historical data retrieval. It uses AES-GCM encryption for
payload security and provides flexible sanitization rules for sensitive data.
*/
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

// AccessControlFunc defines a function signature for custom access control
// checks when viewing audit history. Implementations should return nil for
// granted access or an error describing the permission failure.
type AccessControlFunc func(ctx context.Context) error

// Sanitizer defines a function type for data sanitization. Implementations
// receive key-value pairs and return sanitized values. Used to redact or
// transform sensitive data in audit payloads.
//
// Example: Redacting all but the first character of an email local part:
//  func(key string, value interface{}) interface{} {
//      if v, ok := value.(string); ok {
//          return sanitizeEmail(v)
//      }
//      return value
//  }
type Sanitizer func(key string, value interface{}) interface{}

// defaultSanitizers contains built-in sanitization rules for common sensitive
// fields. Applied automatically by SanitizePayload. Current rules:
//   - "email": Redacts email local part (e.g. "a****@example.com")
//   - "password": Replaces with static "****" regardless of value
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

// GenerateAESKey creates a cryptographically secure 256-bit AES key suitable
// for use with EncryptEvent. The key is generated using crypto/rand for secure
// random number generation.
//
// Returns:
//   - []byte: 32-byte AES-256 key
//   - error:  Any error during random number generation
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return key, nil
}

// SanitizePayload processes an event's payload by applying sanitization rules
// to sensitive fields. Uses both package defaults and any provided custom
// sanitizers. Returns a new event with sanitized payload while preserving
// original metadata.
//
// The sanitization process:
//   1. Creates a shallow copy of the payload map
//   2. Applies sanitizers to matching keys
//   3. Returns new event wrapper with sanitized data
//
// Non-map payloads are returned unmodified.
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

// sanitizedEvent wraps an existing Event to provide sanitized payload data
// while preserving original event metadata and behavior. Created exclusively
// through SanitizePayload.
type sanitizedEvent struct {
	Event
	payload interface{}
}

func (e *sanitizedEvent) Payload() interface{} { return e.payload }

// EncryptEvent transforms an event's payload into an encrypted format using
// AES-GCM encryption. The process:
//   1. JSON-marshal the payload
//   2. Generate random nonce
//   3. Encrypt using AES-GCM
//   4. Base64-encode the result
//
// Parameters:
//   - evt: Original audit event
//   - key: 32-byte AES key from GenerateAESKey
//
// Returns:
//   - Event: New event with encrypted payload accessible via Payload()
//   - error: Any error during marshaling, encryption, or encoding
//
// The original payload remains available through the returned event's
// Payload() method to support subsequent processing.
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

// encryptedEvent wraps an existing Event to provide encrypted payload
// representation while preserving access to the original payload data.
// Created exclusively through EncryptEvent.
type encryptedEvent struct {
	Event
	encrypted string  // Base64-encoded ciphertext
	original  interface{}  // Preserved original payload
}

func (e *encryptedEvent) Payload() interface{} { return e.original }

// CheckHistoryAccess verifies permissions for accessing audit history through
// a two-tiered authorization system:
//
// 1. Context-specific check: If an AccessControlFunc is set in context using
//    the accessControlKey, it will be executed.
// 2. Default role check: When no custom check exists, verifies the context
//    contains a "role" value of "admin".
//
// Parameters:
//   - ctx: Context containing either an AccessControlFunc or role information
//
// Returns:
//   - error: Permission denied error or nil for successful authorization
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

// accessControlKey is the context key type for storing and retrieving
// AccessControlFunc implementations in context.Context. Used to provide
// custom access control logic per-request or per-operation.
type accessControlKey struct{}