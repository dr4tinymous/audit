package audit

import (
	"os"
	"strconv"
	"time"
	"github.com/prometheus/client_golang/prometheus"
)

// BusOption defines a functional option for configuring Bus.
type BusOption func(*BusConfig)

// WithHistoryCap sets the history buffer size.
func WithHistoryCap(n int) BusOption {
	return func(cfg *BusConfig) { cfg.HistoryCap = n }
}

// WithBufferSize sets the async queue size.
func WithBufferSize(n int) BusOption {
	return func(cfg *BusConfig) { cfg.BufferSize = n }
}

// WithWorkerCount sets the number of workers.
func WithWorkerCount(n int) BusOption {
	return func(cfg *BusConfig) { cfg.WorkerCount = n }
}

// WithAsync enables or disables async delivery.
func WithAsync(async bool) BusOption {
	return func(cfg *BusConfig) { cfg.Async = async }
}

// WithSampleRate sets the sampling rate.
func WithSampleRate(rate float64) BusOption {
	return func(cfg *BusConfig) { cfg.SampleRate = rate }
}

// WithSpilloverDir sets the spillover directory.
func WithSpilloverDir(dir string) BusOption {
	return func(cfg *BusConfig) { cfg.SpilloverDir = dir }
}

// WithMaxMemoryMB sets the memory limit in MB.
func WithMaxMemoryMB(mb int) BusOption {
	return func(cfg *BusConfig) { cfg.MaxMemoryMB = mb }
}

// WithCircuitBreaker sets circuit breaker parameters.
func WithCircuitBreaker(timeout time.Duration, maxFails int) BusOption {
	return func(cfg *BusConfig) {
		cfg.CircuitTimeout = timeout
		cfg.CircuitMaxFails = maxFails
	}
}

// WithMetrics sets the metrics implementation.
func WithMetrics(metrics BusMetrics) BusOption {
	return func(cfg *BusConfig) { cfg.Metrics = metrics }
}

// WithTransport sets the external transport.
func WithTransport(transport Transport) BusOption {
	return func(cfg *BusConfig) { cfg.Transport = transport }
}

// WithAccessControl sets the access control function for history access.
func WithAccessControl(f AccessControlFunc) BusOption {
	return func(cfg *BusConfig) { cfg.AccessControl = f }
}

// WithRateLimit sets the rate limit for event publishing (events per second) and burst size.
func WithRateLimit(rate, burst int) BusOption {
	return func(cfg *BusConfig) {
		cfg.RateLimit = rate
		cfg.RateBurst = burst
	}
}

// LoadConfigFromEnv loads configuration from environment variables.
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
			opts = append(opts, WithRateLimit(n, n))
		}
	}
	return opts
}

// WithMetricsRegisterer sets the Prometheus registerer for metrics.
func WithMetricsRegisterer(registerer prometheus.Registerer) BusOption {
	return func(cfg *BusConfig) {
		cfg.Metrics = NewPrometheusMetrics(registerer)
	}
}