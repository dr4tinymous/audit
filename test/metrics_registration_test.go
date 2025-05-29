package audit_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/dr4tinymous/audit"
)

func TestMetricsRegistration(t *testing.T) {
	reg1 := prometheus.NewRegistry()
	reg2 := prometheus.NewRegistry()

	bus1, _ := audit.NewBus(audit.WithMetrics(audit.NewPrometheusMetrics(reg1)))
	defer bus1.Close()
	bus2, _ := audit.NewBus(audit.WithMetrics(audit.NewPrometheusMetrics(reg2)))
	defer bus2.Close()

	evt := audit.NewBasicEvent("test_event", "source", "ctx", nil, nil)
	bus1.Publish(evt)
	bus2.Publish(evt)
	time.Sleep(50 * time.Millisecond)

	c1, _ := testutil.GatherAndCount(reg1, "audit_events_published_total")
	c2, _ := testutil.GatherAndCount(reg2, "audit_events_published_total")
	if c1 != 1 || c2 != 1 {
		t.Errorf("Expected 1 event per registry, got bus1=%d, bus2=%d", c1, c2)
	}
}
