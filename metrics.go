package audit

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// BusMetrics defines the interface for collecting operational metrics related to the audit bus.
// Implementations of this interface allow the audit package to report various activities
// such as event publishing, dropping, and processing latency to a monitoring system.
type BusMetrics interface {
	// EventPublished increments a counter indicating that an audit event of a specific type
	// was successfully published.
	EventPublished(et EventType)

	// EventDropped increments a counter indicating that an audit event of a specific type
	// was dropped, typically due to rate limiting, full buffers, or other internal errors.
	EventDropped(et EventType)

	// HandlerLatency records the processing duration for an audit event by a handler.
	// This metric helps in monitoring the performance of event processing.
	HandlerLatency(et EventType, d time.Duration)
}

// PrometheusMetrics implements the BusMetrics interface using Prometheus.
// It exposes audit-related metrics as Prometheus counters and histograms,
// making them discoverable and scrapable by a Prometheus server.
type PrometheusMetrics struct {
	// published is a Prometheus CounterVec that tracks the total number of
	// audit events successfully published, labeled by event type.
	published *prometheus.CounterVec

	// dropped is a Prometheus CounterVec that tracks the total number of
	// audit events that were dropped, labeled by event type.
	dropped *prometheus.CounterVec

	// latency is a Prometheus HistogramVec that records the distribution of
	// audit event handler latencies in seconds, labeled by event type.
	latency *prometheus.HistogramVec
}

// NewPrometheusMetrics creates a new PrometheusMetrics instance and registers
// its associated Prometheus collectors (counters and histograms) with the
// provided Prometheus registerer.
//
// If the `registerer` is nil, it defaults to `prometheus.DefaultRegisterer`.
// This function panics if metric registration fails, as is common practice
// for Prometheus metric initialization to ensure critical metrics are always available.
//
// Parameters:
//   - registerer: The Prometheus Registerer to use for registering the metrics.
//     If nil, `prometheus.DefaultRegisterer` will be used.
//
// Returns:
//   - *PrometheusMetrics: A pointer to the initialized PrometheusMetrics instance.
func NewPrometheusMetrics(registerer prometheus.Registerer) *PrometheusMetrics {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	m := &PrometheusMetrics{
		published: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "audit_events_published_total",
				Help: "Total number of audit events successfully published.",
			},
			[]string{"event_type"}, // Label for different event types
		),
		dropped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "audit_events_dropped_total",
				Help: "Total number of audit events dropped.",
			},
			[]string{"event_type"}, // Label for different event types
		),
		latency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "audit_handler_latency_seconds",
				Help:    "Latency of audit event handlers in seconds.",
				Buckets: prometheus.DefBuckets, // Use default Prometheus histogram buckets
			},
			[]string{"event_type"}, // Label for different event types
		),
	}
	// Register all collectors. MustRegister panics on error, which is desired for
	// critical metric setup in many applications.
	registerer.MustRegister(m.published, m.dropped, m.latency)
	return m
}

// EventPublished increments the 'audit_events_published_total' counter
// for the given event type.
func (m *PrometheusMetrics) EventPublished(et EventType) {
	m.published.WithLabelValues(string(et)).Inc()
}

// EventDropped increments the 'audit_events_dropped_total' counter
// for the given event type.
func (m *PrometheusMetrics) EventDropped(et EventType) {
	m.dropped.WithLabelValues(string(et)).Inc()
}

// HandlerLatency records the duration 'd' in seconds to the
// 'audit_handler_latency_seconds' histogram for the given event type.
func (m *PrometheusMetrics) HandlerLatency(et EventType, d time.Duration) {
	m.latency.WithLabelValues(string(et)).Observe(d.Seconds())
}

// nopMetrics is a no-operation (no-op) implementation of the BusMetrics interface.
// It serves as a dummy implementation that performs no action when its methods are called,
// useful for disabling metrics collection when it's not required or for testing.
type nopMetrics struct{}

// EventPublished does nothing for nopMetrics.
func (nopMetrics) EventPublished(et EventType) {}

// EventDropped does nothing for nopMetrics.
func (nopMetrics) EventDropped(et EventType) {}

// HandlerLatency does nothing for nopMetrics.
func (nopMetrics) HandlerLatency(et EventType, d time.Duration) {}