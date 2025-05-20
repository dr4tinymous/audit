package audit

import (
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Package audit provides a robust and configurable event auditing bus for applications.
// It allows for asynchronous event delivery, history buffering, rate limiting, and spillover
// to disk, ensuring reliable event capture even under high load or transient external service
// unavailability. The bus is designed to be highly configurable through functional options
// and supports integration with Prometheus for metrics and a custom transport for event delivery.

// BusOption defines a functional option for configuring a Bus instance.
// Functional options provide a clean and extensible way to configure a Bus
// without requiring complex constructors with many parameters.
type BusOption func(*BusConfig)

// WithHistoryCap sets the capacity of the in-memory history buffer.
//
// The history buffer stores a fixed number of the most recent audit events,
// which can be useful for debugging or replaying events. A value of 0 disables
// history buffering.
func WithHistoryCap(n int) BusOption {
	return func(cfg *BusConfig) { cfg.HistoryCap = n }
}

// WithBufferSize sets the capacity of the internal asynchronous event queue.
//
// When async delivery is enabled, events are placed into this buffer before
// being processed by workers. A larger buffer can absorb temporary spikes
// in event volume, while a smaller one can help surface backpressure faster.
// A value of 0 indicates an unbuffered channel.
func WithBufferSize(n int) BusOption {
	return func(cfg *BusConfig) { cfg.BufferSize = n }
}

// WithWorkerCount sets the number of concurrent goroutines (workers) that process
// events from the asynchronous queue.
//
// More workers can increase throughput but also consume more resources.
// This option is only effective when asynchronous delivery is enabled.
func WithWorkerCount(n int) BusOption {
	return func(cfg *BusConfig) { cfg.WorkerCount = n }
}

// WithAsync enables or disables asynchronous event delivery.
//
// When async is true, events are placed into an internal buffer and processed
// by a pool of workers in the background, allowing the Publish call to return
// quickly. When async is false, events are delivered synchronously, blocking
// the caller until the event is processed by the underlying Transport.
func WithAsync(async bool) BusOption {
	return func(cfg *BusConfig) { cfg.Async = async }
}

// WithSampleRate sets the sampling rate for audit events.
//
// This allows for publishing only a fraction of all generated events.
// The rate must be a float64 between 0.0 and 1.0 (inclusive).
// A rate of 1.0 means all events are published; a rate of 0.5 means
// approximately half of the events are published.
func WithSampleRate(rate float64) BusOption {
	return func(cfg *BusConfig) { cfg.SampleRate = rate }
}

// WithSpilloverDir sets the directory path for storing spilled-over events.
//
// If configured, events that cannot be delivered (e.g., due to circuit breaker
// open or full buffer) will be written to files in this directory.
// This helps prevent data loss during periods of high load or transport
// unavailability. An empty string disables spillover to disk.
func WithSpilloverDir(dir string) BusOption {
	return func(cfg *BusConfig) { cfg.SpilloverDir = dir }
}

// WithMaxMemoryMB sets the maximum amount of memory (in megabytes) that the
// audit bus is allowed to consume for its internal buffers and event history.
//
// This includes the async queue and history buffer. When this limit is approached,
// the bus may prioritize discarding older events or blocking new ones to
// prevent excessive memory usage. A value of 0 indicates no memory limit.
func WithMaxMemoryMB(mb int) BusOption {
	return func(cfg *BusConfig) { cfg.MaxMemoryMB = mb }
}

// WithCircuitBreaker configures the circuit breaker parameters for the underlying Transport.
//
// The circuit breaker helps prevent repeated attempts to an unresponsive external service
// by temporarily "opening" and failing fast after a certain number of consecutive failures.
//
//   - timeout: The duration after which a failed circuit will attempt to "half-open"
//     and try sending a single request to check if the transport has recovered.
//   - maxFails: The number of consecutive failures that will cause the circuit to "open".
func WithCircuitBreaker(timeout time.Duration, maxFails int) BusOption {
	return func(cfg *BusConfig) {
		cfg.CircuitTimeout = timeout
		cfg.CircuitMaxFails = maxFails
	}
}

// WithMetrics sets the custom implementation for collecting audit bus metrics.
//
// This allows integrating with various monitoring systems. If not set, a no-op
// metrics implementation will be used, meaning no metrics are collected.
// Use WithMetricsRegisterer for Prometheus integration.
func WithMetrics(metrics BusMetrics) BusOption {
	return func(cfg *BusConfig) { cfg.Metrics = metrics }
}

// WithTransport sets the external Transport responsible for delivering audit events.
//
// This is a mandatory option as the Transport defines where and how audit events
// are ultimately sent (e.g., to a log file, a Kafka topic, or an external API).
// If not provided, the bus will not be able to deliver events.
func WithTransport(transport Transport) BusOption {
	return func(cfg *BusConfig) { cfg.Transport = transport }
}

// WithAccessControl sets a function to control access to the historical events buffer.
//
// The provided AccessControlFunc will be invoked with a context.Context
// and an audit.Event, returning an error if access is denied. This can be used
// to implement fine-grained permissions for viewing sensitive historical data.
func WithAccessControl(f AccessControlFunc) BusOption {
	return func(cfg *BusConfig) { cfg.AccessControl = f }
}

// WithRateLimit sets the maximum publishing rate and burst size for audit events.
//
// This prevents the audit bus from overwhelming downstream services or local resources
// during peak load. Events exceeding the rate limit will be dropped.
//
//   - rate: The average number of events per second that can be published.
//   - burst: The maximum number of events that can be published in a short burst
//     before rate limiting applies.
func WithRateLimit(rate, burst int) BusOption {
	return func(cfg *BusConfig) {
		cfg.RateLimit = rate
		cfg.RateBurst = burst
	}
}

// LoadConfigFromEnv loads configuration options for the audit bus from environment variables.
//
// This function provides a convenient way to configure the bus externally.
// It parses specific environment variables and returns a slice of BusOption functions.
// If an environment variable is malformed or not set, it is ignored.
//
// Supported environment variables:
//   - AUDIT_HISTORY_CAP: Sets the history buffer capacity (integer).
//   - AUDIT_BUFFER_SIZE: Sets the async queue buffer size (integer).
//   - AUDIT_SAMPLE_RATE: Sets the event sampling rate (float64).
//   - AUDIT_SPILLOVER_DIR: Sets the directory for spilled-over events (string).
//   - AUDIT_RATE_LIMIT: Sets the rate limit (events per second) and uses the same
//     value for the burst size (integer).
func LoadConfigFromEnv() []BusOption {
	var opts []BusOption
	if v := os.Getenv("AUDIT_HISTORY_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			opts = append(opts, WithHistoryCap(n))
		}
	}
	if v := os.Getenv("AUDIT_BUFFER_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			opts = append(opts, WithBufferSize(n))
		}
	}
	if v := os.Getenv("AUDIT_SAMPLE_RATE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			opts = append(opts, WithSampleRate(f))
		}
	}
	if v := os.Getenv("AUDIT_SPILLOVER_DIR"); v != "" {
		opts = append(opts, WithSpilloverDir(v))
	}
	if v := os.Getenv("AUDIT_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			// When loaded from env, rate and burst are set to the same value
			opts = append(opts, WithRateLimit(n, n))
		}
	}
	return opts
}

// WithMetricsRegisterer sets the Prometheus registerer to automatically
// initialize and register Prometheus metrics for the audit bus.
//
// This is a convenience function that uses the provided prometheus.Registerer
// to create a new PrometheusMetrics instance and sets it via WithMetrics.
// Use this if you are using Prometheus for your application's metrics.
func WithMetricsRegisterer(registerer prometheus.Registerer) BusOption {
	return func(cfg *BusConfig) {
		cfg.Metrics = NewPrometheusMetrics(registerer)
	}
}