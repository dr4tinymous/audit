package audit_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/dr4tinymous/audit"
)

func TestCheckHistoryAccess(t *testing.T) {
	bus, err := audit.NewBus(
		audit.WithAccessControl(func(ctx context.Context) error {
			if role, ok := ctx.Value("role").(string); ok && role == "admin" {
				return nil
			}
			return fmt.Errorf("access denied")
		}),
	)
	if err != nil {
		t.Fatalf("Failed to create bus: %v", err)
	}
	defer bus.Close()

	// Admin should succeed
	if _, err := bus.History(adminCtx()); err != nil {
		t.Errorf("Expected no error for admin role, got: %v", err)
	}

	// Non-admin should be denied
	userCtx := context.WithValue(context.Background(), "role", "user")
	if _, err := bus.History(userCtx); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Errorf("Expected access denied error for non-admin, got: %v", err)
	}
}
