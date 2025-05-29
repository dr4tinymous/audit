package audit_test

import (
	"context"
)

// adminCtx returns a context with an "admin" role for access-control tests.
func adminCtx() context.Context {
	return context.WithValue(context.Background(), "role", "admin")
}
