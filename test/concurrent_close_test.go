package audit_test

import (
	"sync"
	"testing"

	"github.com/dr4tinymous/audit"
)

func TestConcurrentClose(t *testing.T) {
	bus, _ := audit.NewBus(audit.WithAsync(true))
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bus.Close()
		}()
	}
	wg.Wait()
	// If we reach here without panic, we pass.
}
