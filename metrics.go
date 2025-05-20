package audit

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// BusMetrics defines the interface for audit bus metrics.
type BusMetrics interface {
	EventPublished(et EventType)
	EventDropped(et EventType)
	HandlerLatency(et EventType, d time.Duration)
}

// PrometheusMetrics implements BusMetrics with Prometheus.
type PrometheusMetrics struct {
	published *prometheus.CounterVec
	dropped   *prometheus.CounterVec
	latency   *prometheus.HistogramVec
}

// NewPrometheusMetrics creates a new PrometheusMetrics instance.
func NewPrometheusMetrics(registerer prometheus.Registerer) *PrometheusMetrics {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	m := &PrometheusMetrics{
		published: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "audit_events_published_total",
				Help: "Total number of audit events published",
			},
			[]string{"event_type"},
		),
		dropped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "audit_events_dropped_total",
				Help: "Total number of audit events dropped",
			},
			[]string{"event_type"},
		),
		latency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "audit_handler_latency_seconds",
				Help:    "Latency of audit event handlers",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"event_type"},
		),
	}
	registerer.MustRegister(m.published, m.dropped, m.latency)
	return m
}

// EventPublished increments the published counter.
func (m *PrometheusMetrics) EventPublished(et EventType) {
	m.published.WithLabelValues(string(et)).Inc()
}

// EventDropped increments the dropped counter.
func (m *PrometheusMetrics) EventDropped(et EventType) {
	m.dropped.WithLabelValues(string(et)).Inc()
}

// HandlerLatency records the handler latency.
func (m *PrometheusMetrics) HandlerLatency(et EventType, d time.Duration) {
	m.latency.WithLabelValues(string(et)).Observe(d.Seconds())
}

// nopMetrics is a no-op BusMetrics implementation.
type nopMetrics struct{}

func (nopMetrics) EventPublished(et EventType)            {}
func (nopMetrics) EventDropped(et EventType)              {}
func (nopMetrics) HandlerLatency(et EventType, d time.Duration) {}