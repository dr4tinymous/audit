// Package audit provides a robust, asynchronous event bus for handling and auditing events
// in a distributed system. It supports features like rate limiting, event spillover to disk,
// circuit breaking, and integration with OpenTelemetry for distributed tracing. The package
// is designed to manage audit events with high reliability, ensuring that events are processed,
// stored, and optionally persisted to disk under high load or failure conditions.
//
// The primary component, Bus, implements a publish/subscribe model where events can be
// dispatched to multiple handlers synchronously or asynchronously. It includes mechanisms
// for sampling, history tracking, and access control, making it suitable for systems requiring
// detailed auditing with performance and fault tolerance in mind.
//
// Key features include:
// - Asynchronous or synchronous event publishing with configurable worker pools.
// - Rate limiting to prevent overload, with spillover to disk for dropped events.
// - Circuit breaker to protect against cascading failures.
// - Event history with configurable capacity and memory limits.
// - Integration with OpenTelemetry for tracing event flows.
// - Customizable error handling and metrics collection.
// - Optional disk-based spillover for event persistence and recovery.
//
// The package is thread-safe and designed for concurrent use in high-throughput environments.
package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
)

// EventType identifies the kind of an audit event.
// It is used to categorize events and allow subscribers to filter events of interest.
type EventType string

// EventAny is a special event type used to subscribe to all events, regardless of their specific type.
// It acts as a wildcard for event handlers that need to process every event published to the bus.
const EventAny EventType = "*"

// Event represents an occurrence to be audited.
// It defines the interface for audit events, capturing essential metadata such as a unique identifier,
// event type, timestamp, source, context ID, payload, and tracing information.
// Implementations of this interface must provide all required metadata to ensure proper auditing.
type Event interface {
	// ID returns the unique identifier for the event.
	// This is typically a UUID to ensure global uniqueness.
	ID() string

	// Type returns the type of the event, used for categorizing and filtering.
	Type() EventType

	// Time returns the timestamp when the event occurred.
	// This is used for temporal ordering and analysis.
	Time() time.Time

	// Source returns the origin or component that generated the event.
	// This helps identify the system or service responsible for the event.
	Source() string

	// ContextID returns a correlation ID for grouping related events.
	// This is useful for tracking events across multiple services or operations.
	ContextID() string

	// Payload returns the event's data payload, which can be any type.
	// The payload contains the specific details or data associated with the event.
	Payload() interface{}

	// SpanContext returns the OpenTelemetry span context for distributed tracing.
	// This allows the event to be correlated with a trace in a distributed system.
	SpanContext() trace.SpanContext
}

// BasicEvent is a simple implementation of the Event interface.
// It provides a straightforward struct for storing audit event data, including
// a unique ID, type, timestamp, source, context ID, payload, and span context.
// This struct is suitable for most use cases where a basic event structure is needed.
type BasicEvent struct {
	IDVal        string            // Unique identifier for the event.
	TypeVal      EventType         // Type of the event for categorization.
	TimeVal      time.Time         // Timestamp when the event occurred.
	SourceVal    string            // Origin or component that generated the event.
	ContextIDVal string            // Correlation ID for grouping related events.
	PayloadVal   interface{}       // Arbitrary data payload of the event.
	SpanCtx      trace.SpanContext // OpenTelemetry span context for tracing.
}

// Ensure BasicEvent implements the Event interface at compile time.
var _ Event = (*BasicEvent)(nil)

// ID returns the unique identifier for the BasicEvent.
// It provides a globally unique string, typically a UUID, to identify the event.
func (e BasicEvent) ID() string {
	return e.IDVal
}

// Type returns the type of the BasicEvent.
// It indicates the category of the event for filtering and processing.
func (e BasicEvent) Type() EventType {
	return e.TypeVal
}

// Time returns the timestamp of the BasicEvent.
// It records when the event occurred, enabling temporal analysis.
func (e BasicEvent) Time() time.Time {
	return e.TimeVal
}

// Source returns the source of the BasicEvent.
// It identifies the system or component that generated the event.
func (e BasicEvent) Source() string {
	return e.SourceVal
}

// ContextID returns the correlation ID of the BasicEvent.
// It allows grouping of related events across services or operations.
func (e BasicEvent) ContextID() string {
	return e.ContextIDVal
}

// Payload returns the data payload of the BasicEvent.
// It contains arbitrary data specific to the event's purpose.
func (e BasicEvent) Payload() interface{} {
	return e.PayloadVal
}

// SpanContext returns the OpenTelemetry span context of the BasicEvent.
// It enables integration with distributed tracing systems.
func (e BasicEvent) SpanContext() trace.SpanContext {
	return e.SpanCtx
}

// NewBasicEvent creates a new BasicEvent with the provided details.
// It initializes the event with a unique ID, current timestamp, and the given type, source,
// context ID, payload, and span context. This function is useful for creating audit events
// with all necessary metadata in a single call.
//
// Parameters:
//   - t: The type of the event, used for categorization and filtering.
//   - source: The origin or component that generated the event.
//   - contextID: A correlation ID for grouping related events.
//   - payload: The arbitrary data associated with the event.
//   - spanCtx: The OpenTelemetry span context for distributed tracing.
//
// Returns:
//   - A BasicEvent instance with the specified fields initialized.
func NewBasicEvent(t EventType, source, contextID string, payload interface{}, spanCtx trace.SpanContext) BasicEvent {
	return BasicEvent{
		IDVal:        uuid.New().String(),
		TypeVal:      t,
		TimeVal:      time.Now(),
		SourceVal:    source,
		ContextIDVal: contextID,
		PayloadVal:   payload,
		SpanCtx:      spanCtx,
	}
}

// BusConfig holds configuration parameters for initializing a Bus.
// It allows customization of the event bus's behavior, including history capacity,
// buffer sizes, worker counts, and various operational settings.
type BusConfig struct {
	HistoryCap      int                 // Maximum number of events to store in history.
	BufferSize      int                 // Size of the event and task queues.
	WorkerCount     int                 // Number of worker goroutines for processing events.
	Async           bool                // Whether to process events asynchronously.
	SampleRate      float64             // Probability of accepting an event (0.0 to 1.0).
	SpilloverDir    string              // Directory for disk-based spillover, if enabled.
	SpillHandler    SpillHandler        // Custom spillover handler, typically for testing.
	MaxMemoryMB     int                 // Maximum memory (in MB) for event history.
	CircuitTimeout  time.Duration       // Duration before resetting the circuit breaker.
	CircuitMaxFails int                 // Maximum failures before opening the circuit breaker.
	RateLimit       int                 // Events per second allowed by the rate limiter.
	RateBurst       int                 // Burst size for the rate limiter.
	ErrorFunc       func(error, Event)  // Callback for handling errors during event processing.
	Metrics         BusMetrics          // Interface for collecting bus metrics.
	Transport       Transport           // Optional transport for sending events externally.
	AccessControl   AccessControlFunc   // Optional function for controlling access to history.
	RecoverInterval time.Duration       // Interval for automatic spillover recovery (0 = disabled).
}

// DefaultBusConfig returns a BusConfig with sensible default values.
// It provides a starting point for configuring a Bus, suitable for most use cases.
// The defaults include asynchronous processing, rate limiting, and a default error handler
// that logs errors with event IDs. Spillover and transport are disabled by default.
//
// Returns:
//   - A BusConfig with default settings.
func DefaultBusConfig() BusConfig {
	return BusConfig{
		HistoryCap:      10000,
		BufferSize:      1000,
		WorkerCount:     8,
		Async:           true,
		SampleRate:      1.0,
		SpilloverDir:    "",
		SpillHandler:    nil,
		MaxMemoryMB:     100,
		CircuitTimeout:  30 * time.Second,
		CircuitMaxFails: 5,
		RateLimit:       1000,
		RateBurst:       1000,
		ErrorFunc:       func(err error, evt Event) { log.Printf("audit.Bus error: %v for event ID %s", err, evt.ID()) },
		Metrics:         nopMetrics{},
		Transport:       nil,
		AccessControl:   nil,
		RecoverInterval: 0,
	}
}

// WithSpilloverHandler creates a BusOption that sets a custom SpillHandler.
// This is typically used in testing to inject an in-memory handler instead of the default
// disk-based spillover handler.
//
// Parameters:
//   - h: The custom SpillHandler to use.
//
// Returns:
//   - A BusOption that sets the SpillHandler in the BusConfig.
func WithSpilloverHandler(h SpillHandler) BusOption {
	return func(cfg *BusConfig) {
		cfg.SpillHandler = h
	}
}

// Bus is an in-memory publish/subscribe bus for audit events.
// It manages the dispatching of events to registered handlers, supports asynchronous
// and synchronous processing, and includes features like rate limiting, event history,
// circuit breaking, and spillover to disk. The bus is thread-safe and designed for
// high-throughput environments with robust error handling and metrics collection.
type Bus struct {
	mu            sync.RWMutex         // Protects handlers and history for concurrent access.
	handlers      map[EventType][]Handler // Maps event types to their registered handlers.
	global        []Handler            // Handlers that receive all events (subscribed to EventAny).
	history       []Event              // In-memory event history.
	historyCap    int                  // Maximum number of events to store in history.
	queueSize     int                  // Size of the event and task queues.
	async         bool                 // Whether the bus operates asynchronously.
	sampleRate    float64              // Probability of accepting an event (0.0 to 1.0).

	spillover     SpillHandler         // Handler for persisting events when rate-limited or queue full.

	errorFunc     func(error, Event)   // Callback for reporting errors.
	metrics       BusMetrics           // Interface for collecting metrics.
	transport     Transport            // Optional transport for external event delivery.
	accessControl AccessControlFunc    // Optional access control for history retrieval.

	eventQueue    chan Event           // Channel for queuing events in async mode.
	taskQueue     chan handlerTask     // Channel for queuing handler tasks in async mode.
	workerWg      sync.WaitGroup       // Wait group for worker goroutines.
	circuit       *circuitBreaker      // Circuit breaker for failure management.
	memoryLimit   int64                // Maximum memory for event history (in bytes).
	memoryUsed    int64                // Current memory used by event history (in bytes).
	closed        atomic.Bool          // Indicates if the bus is closed.

	limiter           *rate.Limiter    // Rate limiter for event publishing.
	recoverScheduled  int32            // Flag to prevent concurrent recovery scheduling.
	queueWg           sync.WaitGroup   // Wait group for queued tasks.
	closeOnce         sync.Once        // Ensures the bus is closed only once.
	stopSpillover     chan struct{}    // Signals background recovery to stop.
	closeStopSpillover sync.Once       // Ensures stopSpillover is closed only once.
}

// NewBus creates a new Bus with the specified configuration options.
// It initializes the bus with handlers, queues, workers, and optional spillover and transport.
// The bus can operate in synchronous or asynchronous mode based on the configuration.
// If a spillover directory is provided, a disk-based handler is created unless a custom
// handler is specified. Errors during initialization (e.g., transport or spillover setup)
// are returned.
//
// Parameters:
//   - opts: Variadic BusOption functions to configure the bus.
//
// Returns:
//   - *Bus: A pointer to the initialized Bus.
//   - error: Any error encountered during initialization (e.g., spillover or transport errors).
func NewBus(opts ...BusOption) (*Bus, error) {
	cfg := DefaultBusConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = nopMetrics{}
	}

	b := &Bus{
		handlers:         make(map[EventType][]Handler),
		history:          make([]Event, 0, cfg.HistoryCap),
		historyCap:       cfg.HistoryCap,
		queueSize:        cfg.BufferSize,
		async:            cfg.Async,
		sampleRate:       cfg.SampleRate,
		errorFunc:        cfg.ErrorFunc,
		metrics:          cfg.Metrics,
		transport:        cfg.Transport,
		accessControl:    cfg.AccessControl,
		memoryLimit:      int64(cfg.MaxMemoryMB) * 1024 * 1024,
		circuit:          newCircuitBreaker(cfg.CircuitTimeout, cfg.CircuitMaxFails),
		limiter:          rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateBurst),
		queueWg:          sync.WaitGroup{},
		closeOnce:        sync.Once{},
		stopSpillover:    make(chan struct{}),
		recoverScheduled: 0,
	}
	log.Printf("audit.Bus: Created with bufferSize=%d, workerCount=%d, async=%v",
		cfg.BufferSize, cfg.WorkerCount, cfg.Async,
	)

	// Initialize spillover handler: prefer test-provided, else disk-based if directory set.
	if cfg.SpillHandler != nil {
		b.spillover = cfg.SpillHandler
	} else if cfg.SpilloverDir != "" {
		var err error
		b.spillover, err = newSpilloverHandler(cfg.SpilloverDir)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize spillover: %w", err)
		}
	}

	// Initialize async mode: start workers, dispatch loop, and optional recovery loop.
	if b.async {
		b.eventQueue = make(chan Event, b.queueSize)
		b.taskQueue = make(chan handlerTask, cfg.BufferSize)
		log.Printf("audit.Bus: Initialized eventQueue with capacity %d", cap(b.eventQueue))

		// Start worker goroutines.
		for i := 0; i < cfg.WorkerCount; i++ {
			b.workerWg.Add(1)
			go b.worker()
		}
		// Start dispatch loop.
		b.workerWg.Add(1)
		go b.dispatchLoop()

		// Start auto-recovery loop if enabled.
		if b.spillover != nil && cfg.RecoverInterval > 0 {
			b.workerWg.Add(1)
			go b.recoverSpilloverLoop(cfg.RecoverInterval)
		}
	}

	// Initialize transport if provided.
	if b.transport != nil {
		if err := b.transport.Start(); err != nil {
			return nil, fmt.Errorf("failed to start transport: %w", err)
		}
		b.Subscribe(EventAny, b.transport.Send)
	}

	return b, nil
}

// Handler defines a function type for processing audit events.
// It takes an Event and returns an error if processing fails. Handlers are registered
// with the bus to receive events of specific types or all events.
type Handler func(evt Event) error

// handlerTask represents a task for the worker pool.
// It pairs a Handler with an Event to be processed by a worker goroutine.
// This struct is used internally to manage asynchronous event processing.
type handlerTask struct {
	h   Handler // The handler to process the event.
	evt Event   // The event to be processed.
}

// DefaultBus creates a Bus with default configuration.
// It is a convenience function for creating a bus with default settings, suitable for
// simple use cases. If initialization fails, it logs a fatal error and terminates.
//
// Returns:
//   - *Bus: A pointer to the initialized Bus.
func DefaultBus() *Bus {
	bus, err := NewBus()
	if err != nil {
		log.Fatalf("Failed to create default bus: %v", err)
	}
	return bus
}

// Close shuts down the Bus, flushing queues and releasing resources.
// It ensures that all worker goroutines and background tasks (e.g., spillover recovery)
// are stopped gracefully. The method is idempotent, meaning multiple calls are safe.
// If the bus is asynchronous, it closes the event and task queues, waits for tasks to
// complete (with a timeout), and closes the spillover and transport if present.
//
// Any errors during resource cleanup are reported via the bus's error handler.
func (b *Bus) Close() {
	if !b.closed.CompareAndSwap(false, true) {
		log.Printf("audit.Bus: Close called on already closed bus")
		return
	}
	log.Printf("audit.Bus: Initiating close, eventQueue len=%d, taskQueue len=%d", len(b.eventQueue), len(b.taskQueue))
	defer func() {
		if b.spillover != nil {
			if err := b.spillover.Close(); err != nil {
				b.errorFunc(fmt.Errorf("spillover close: %w", err), nil)
			}
		}
		if b.transport != nil {
			if err := b.transport.Close(); err != nil {
				b.errorFunc(fmt.Errorf("transport close: %w", err), nil)
			}
		}
		log.Printf("audit.Bus: Close completed")
	}()
	if b.async {
		// Signal background recovery to stop.
		b.closeStopSpillover.Do(func() {
			close(b.stopSpillover)
		})
		// Close event and task queues.
		b.closeOnce.Do(func() {
			log.Printf("audit.Bus: Closing eventQueue")
			if b.eventQueue != nil {
				close(b.eventQueue)
			}
			log.Printf("audit.Bus: Closing taskQueue")
			if b.taskQueue != nil {
				close(b.taskQueue)
			}
		})
		// Wait for tasks with timeout.
		done := make(chan struct{})
		go func() {
			b.queueWg.Wait()
			close(done)
		}()
		select {
		case <-done:
			log.Printf("audit.Bus: All tasks completed")
		case <-time.After(5 * time.Second):
			log.Printf("audit.Bus: Timeout waiting for tasks")
		}
		b.workerWg.Wait()
	}
}

// dispatchLoop processes events from the event queue, dispatching to handlers.
// It runs in a dedicated goroutine in async mode, reading events from the event queue
// and dispatching them to the appropriate handlers (specific to the event type or global).
// The loop exits when the event queue is closed or the stopSpillover signal is received.
// This method is internal and not exported.
func (b *Bus) dispatchLoop() {
	defer b.workerWg.Done()
	for {
		select {
		case evt, ok := <-b.eventQueue:
			if !ok {
				log.Printf("audit.Bus: dispatchLoop exiting, eventQueue closed")
				return // eventQueue closed
			}
			b.mu.RLock()
			local := append([]Handler(nil), b.handlers[evt.Type()]...)
			global := append([]Handler(nil), b.global...)
			b.mu.RUnlock()
			if len(local)+len(global) == 0 {
				continue // No handlers, skip
			}
			log.Printf("audit.Bus: Dispatching event ID %s to %d handlers", evt.ID(), len(local)+len(global))
			for _, h := range append(local, global...) {
				select {
				case b.taskQueue <- handlerTask{h, evt}:
					// queueWg.Add/Done handled in worker
				case <-b.stopSpillover:
					log.Printf("audit.Bus: dispatchLoop exiting, stopSpillover signaled")
					return
				}
			}
		case <-b.stopSpillover:
			log.Printf("audit.Bus: dispatchLoop exiting, stopSpillover signaled")
			return
		}
	}
}

// worker processes handler tasks from the task queue.
// It runs in a worker goroutine in async mode, executing handlers for events
// received from the task queue. It handles panics, records handler latency,
// and updates the circuit breaker based on success or failure. The worker exits
// when the task queue is closed or the stopSpillover signal is received.
// This method is internal and not exported.
func (b *Bus) worker() {
	defer b.workerWg.Done()
	for {
		select {
		case task, ok := <-b.taskQueue:
			if !ok {
				log.Printf("audit.Bus: worker exiting, taskQueue closed")
				return // taskQueue closed
			}
			b.queueWg.Add(1)
			log.Printf("audit.Bus: Processing task for event ID %s", task.evt.ID())
			start := time.Now()
			func() {
				defer func() {
					b.queueWg.Done()
					if r := recover(); r != nil {
						b.circuit.RecordFailure()
						b.errorFunc(fmt.Errorf("handler panic: %v", r), task.evt)
					}
					b.metrics.HandlerLatency(task.evt.Type(), time.Since(start))
				}()
				if err := task.h(task.evt); err != nil {
					b.circuit.RecordFailure()
					b.errorFunc(err, task.evt)
				} else {
					b.circuit.RecordSuccess()
				}
			}()
		case <-b.stopSpillover:
			log.Printf("audit.Bus: worker exiting, stopSpillover signaled")
			return
		}
	}
}

// Subscribe registers a handler for a specific event type or all events.
// It associates the handler with the given event type, or with all events if `EventAny` is specified.
// The bus is thread-safe, and this method uses a lock to ensure safe concurrent registration.
//
// Parameters:
//   - et: The event type to subscribe to, or `EventAny` for all events.
//   - h: The handler function to process events.
func (b *Bus) Subscribe(et EventType, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if et == EventAny {
		b.global = append(b.global, h)
	} else {
		b.handlers[et] = append(b.handlers[et], h)
	}
}

// ErrPublishTimeout is an error returned when an event cannot be enqueued within the specified timeout.
var ErrPublishTimeout = fmt.Errorf("audit bus: publish timeout")

// scheduleRecoverDebounced schedules a debounced recovery of spilled events.
// It ensures that only one recovery is scheduled per burst of rate-limited events,
// delaying the recovery to allow file writes to settle. This method is internal and not exported.
func (b *Bus) scheduleRecoverDebounced() {
	// Only schedule once per burst.
	if !atomic.CompareAndSwapInt32(&b.recoverScheduled, 0, 1) {
		return
	}
	go func() {
		// Wait for file writes to settle (and for tests to scan).
		time.Sleep(100 * time.Millisecond)
		if err := b.RecoverSpillover(); err != nil {
			b.errorFunc(fmt.Errorf("auto-recover after rate-limit: %w", err), nil)
		}
		// Allow future bursts to schedule again.
		atomic.StoreInt32(&b.recoverScheduled, 0)
	}()
}

// Publish publishes an event to the bus, with rate limiting and debounced auto-recovery.
// It checks if the bus is closed, applies rate limiting, prepares the event (ensuring ID,
// timestamp, and span context), and dispatches it either synchronously or asynchronously
// based on the bus configuration. If rate-limited or the queue is full, the event is spilled
// to the configured SpillHandler.
//
// Parameters:
//   - evt: The event to publish.
func (b *Bus) Publish(evt Event) {
	// Drop if bus is closed.
	if b.closed.Load() {
		b.errorFunc(fmt.Errorf("bus closed"), evt)
		return
	}

	// Apply rate limiting.
	if b.limiter != nil && !b.limiter.Allow() {
		b.spillEvent(evt)
		b.metrics.EventDropped(evt.Type())
		b.errorFunc(fmt.Errorf("rate limit exceeded"), evt)
		b.scheduleRecoverDebounced()
		return
	}

	// Prepare the event.
	evt = b.prepareEvent(evt)
	if evt == nil {
		return
	}

	// Dispatch the event.
	if b.async {
		b.publishAsync(evt)
	} else {
		b.publishSync(evt)
	}
}

// PublishSync publishes an event synchronously.
// It checks if the bus is closed, prepares the event, and dispatches it to all relevant
// handlers synchronously. If the bus is closed or the event fails preparation, it reports
// an error via the error handler.
//
// Parameters:
//   - evt: The event to publish.
func (b *Bus) PublishSync(evt Event) {
	if b.closed.Load() {
		b.errorFunc(fmt.Errorf("bus closed"), evt)
		return
	}
	evt = b.prepareEvent(evt)
	if evt == nil {
		return
	}
	b.publishSync(evt)
}

// PublishWithTimeout publishes an event with a timeout for enqueueing.
// It checks if the bus is closed, applies rate limiting, prepares the event, and attempts
// to enqueue it within the specified timeout (in async mode). If the bus is closed, rate-limited,
// or the circuit breaker is open, the event is spilled. If the enqueue times out, an error is returned.
//
// Parameters:
//   - evt: The event to publish.
//   - timeout: The maximum duration to wait for enqueueing in async mode.
//
// Returns:
//   - error: Any error encountered (e.g., bus closed, rate limit exceeded, timeout, or queue closed).
func (b *Bus) PublishWithTimeout(evt Event, timeout time.Duration) error {
	if b.closed.Load() {
		b.errorFunc(fmt.Errorf("bus closed"), evt)
		return fmt.Errorf("bus closed")
	}
	if b.limiter != nil && !b.limiter.Allow() {
		b.spillEvent(evt)
		b.metrics.EventDropped(evt.Type())
		b.errorFunc(fmt.Errorf("rate limit exceeded"), evt)
		return fmt.Errorf("rate limit exceeded")
	}
	evt = b.prepareEvent(evt)
	if evt == nil {
		return nil
	}
	if !b.async {
		b.publishSync(evt)
		return nil
	}
	if !b.circuit.IsClosed() {
		b.spillEvent(evt)
		b.metrics.EventDropped(evt.Type())
		b.errorFunc(fmt.Errorf("circuit breaker open"), evt)
		return fmt.Errorf("circuit breaker open")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case b.eventQueue <- evt:
		b.metrics.EventPublished(evt.Type())
		return nil
	case <-timer.C:
		b.spillEvent(evt)
		b.metrics.EventDropped(evt.Type())
		b.errorFunc(ErrPublishTimeout, evt)
		return ErrPublishTimeout
	case <-b.eventQueue: // Guard against closed channel
		b.errorFunc(fmt.Errorf("event queue closed"), evt)
		return fmt.Errorf("event queue closed")
	}
}

// History returns the event history.
// It retrieves a copy of the in-memory event history, applying access control if configured.
// If access is denied, an error is returned. The method is thread-safe and ensures the
// history is not modified during access.
//
// Parameters:
//   - ctx: The context for access control checks.
//
// Returns:
//   - []Event: A slice of events in the history.
//   - error: Any error from access control or history retrieval.
func (b *Bus) History(ctx context.Context) ([]Event, error) {
	if b.accessControl != nil {
		if err := b.accessControl(ctx); err != nil {
			return nil, err
		}
	} else if err := CheckHistoryAccess(ctx); err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	hs := make([]Event, len(b.history))
	copy(hs, b.history)
	return hs, nil
}

// SetHistoryCap sets the maximum number of events to store in history.
// It adjusts the history capacity and trims the history if necessary, updating the memory usage.
// If the capacity is set to 0, the history is cleared. The method is thread-safe.
//
// Parameters:
//   - n: The new history capacity (maximum number of events).
func (b *Bus) SetHistoryCap(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.historyCap = n
	if n <= 0 {
		b.history = nil
		b.memoryUsed = 0
		return
	}
	if len(b.history) > n {
		excess := b.history[:len(b.history)-n]
		for _, evt := range excess {
			b.memoryUsed -= estimateEventSize(evt)
		}
		b.history = b.history[len(b.history)-n:]
	}
}

// SetSampleRate sets the sampling rate for events.
// It updates the probability of accepting an event, ensuring the rate is between 0.0 and 1.0.
// Invalid rates are ignored. The method is thread-safe.
//
// Parameters:
//   - rate: The sampling rate (0.0 to 1.0).
func (b *Bus) SetSampleRate(rate float64) {
	if rate < 0 || rate > 1 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sampleRate = rate
}

// prepareEvent prepares an event for publishing.
// It ensures the event has a valid ID, timestamp, and span context, validates and sanitizes
// the payload, applies sampling, and checks memory limits. If any check fails, the event
// is dropped or spilled, and nil is returned. This method is internal and not exported.
//
// Parameters:
//   - evt: The event to prepare.
//
// Returns:
//   - Event: The prepared event, or nil if it was dropped.
func (b *Bus) prepareEvent(evt Event) Event {
	evt = ensureID(evt)
	evt = ensureTime(evt)
	evt = ensureSpanContext(evt)
	if err := validatePayload(evt); err != nil {
		b.errorFunc(err, evt)
		return nil
	}
	evt = SanitizePayload(evt)
	if !b.shouldSample() {
		b.metrics.EventDropped(evt.Type())
		return nil
	}
	if !b.canStoreEvent(evt) {
		b.spillEvent(evt)
		b.metrics.EventDropped(evt.Type())
		return nil
	}
	b.recordHistory(evt)
	return evt
}

// publishAsync publishes an event asynchronously.
// It attempts to enqueue the event for processing by workers. If the circuit breaker is open
// or the queue is full, the event is spilled. This method is internal and not exported.
//
// Parameters:
//   - evt: The event to publish.
func (b *Bus) publishAsync(evt Event) {
	if !b.circuit.IsClosed() {
		b.spillEvent(evt)
		b.metrics.EventDropped(evt.Type())
		return
	}
	select {
	case b.eventQueue <- evt:
		b.metrics.EventPublished(evt.Type())
	default:
		log.Printf("audit.Bus: Queue full, spilling event ID %s", evt.ID())
		b.spillEvent(evt)
		b.metrics.EventDropped(evt.Type())
		b.errorFunc(fmt.Errorf("event dropped, queue full"), evt)
	}
}

// publishSync dispatches an event synchronously to all relevant handlers.
// It executes handlers for the event type and global handlers, handling panics and updating
// the circuit breaker. If the circuit breaker is open, the event is spilled.
// This method is internal and not exported.
//
// Parameters:
//   - evt: The event to publish.
func (b *Bus) publishSync(evt Event) {
	if !b.circuit.IsClosed() {
		b.spillEvent(evt)
		b.metrics.EventDropped(evt.Type())
		return
	}
	b.mu.RLock()
	local := append([]Handler(nil), b.handlers[evt.Type()]...)
	global := append([]Handler(nil), b.global...)
	b.mu.RUnlock()
	b.queueWg.Add(1)
	defer b.queueWg.Done()
	for _, h := range append(local, global...) {
		start := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					b.circuit.RecordFailure()
					b.errorFunc(fmt.Errorf("handler panic: %v", r), evt)
				}
				b.metrics.HandlerLatency(evt.Type(), time.Since(start))
			}()
			if err := h(evt); err != nil {
				b.circuit.RecordFailure()
				b.errorFunc(err, evt)
			} else {
				b.circuit.RecordSuccess()
			}
		}()
	}
}

// recordHistory records an event in the in-memory history.
// It skips duplicate events (by ID), trims the history if it exceeds the capacity,
// and updates the memory usage. This method is internal and not exported.
//
// Parameters:
//   - evt: The event to record.
func (b *Bus) recordHistory(evt Event) {
	if b.historyCap <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	// Skip if event ID already exists.
	for _, existing := range b.history {
		if existing.ID() == evt.ID() {
			return
		}
	}

	if len(b.history) >= b.historyCap {
		excess := b.history[0]
		b.memoryUsed -= estimateEventSize(excess)
		b.history = b.history[1:]
	}
	b.history = append(b.history, evt)
	b.memoryUsed += estimateEventSize(evt)
}

// canStoreEvent checks if an event can be stored within memory limits.
// It estimates the event's size and compares it against the remaining memory budget.
// This method is internal and not exported.
//
// Parameters:
//   - evt: The event to check.
//
// Returns:
//   - bool: True if the event can be stored, false otherwise.
func (b *Bus) canStoreEvent(evt Event) bool {
	size := estimateEventSize(evt)
	if atomic.LoadInt64(&b.memoryUsed)+size > b.memoryLimit {
		return false
	}
	return true
}

// SpillHandler defines the interface for handling event spillover.
// It is used to persist events to a storage medium (e.g., disk or in-memory) when
// the event bus cannot process them immediately due to rate limits or queue capacity.
// Implementations must handle writing events and closing resources cleanly.
type SpillHandler interface {
	// Write persists an event to the underlying storage medium.
	// It returns an error if the write operation fails.
	// Parameters:
	//   - evt: The event to be written.
	// Returns:
	//   - error: Any error encountered during the write operation.
	Write(Event) error

	// Close releases any resources held by the handler.
	// It returns an error if the close operation fails.
	// Returns:
	//   - error: Any error encountered during the close operation.
	Close() error
}

// spillEvent writes an event to the spillover handler.
// It persists the event to disk or another medium if a SpillHandler is configured.
// This method is internal and not exported.
//
// Parameters:
//   - evt: The event to spill.
func (b *Bus) spillEvent(evt Event) {
	if b.spillover != nil {
		log.Printf("audit.Bus: Spilling event ID %s", evt.ID())
		_ = b.spillover.Write(evt)
	}
}

// shouldSample determines if an event should be sampled based on the sampling rate.
// It returns true if the event should be processed, false if it should be dropped.
// This method is internal and not exported.
//
// Returns:
//   - bool: True if the event should be sampled, false otherwise.
func (b *Bus) shouldSample() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sampleRate == 1.0 || rand.Float64() < b.sampleRate
}

// recoverSpilloverLoop periodically attempts to recover events from spillover.
// It runs in a background goroutine, checking for spilled events at the configured interval.
// Recovery only occurs when the event queue is empty and the circuit breaker is closed.
// This method is internal and not exported.
//
// Parameters:
//   - interval: The interval between recovery attempts.
func (b *Bus) recoverSpilloverLoop(interval time.Duration) {
	defer b.workerWg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopSpillover:
			return
		case <-ticker.C:
			if b.closed.Load() {
				return
			}
			// Only replay spilled events when queue is empty and circuit is closed.
			if b.eventQueue != nil && len(b.eventQueue) == 0 && b.circuit.IsClosed() {
				if err := b.RecoverSpillover(); err != nil {
					b.errorFunc(fmt.Errorf("spillover recovery: %w", err), nil)
				}
			}
		}
	}
}

// RecoverSpillover recovers events from the spillover file and republishes them.
// It reads events from the spillover file (if disk-based), deserializes them, and publishes
// them synchronously. The file is truncated after successful recovery. If the bus is closed
// or no spillover handler is configured, it returns early. Errors are returned if file operations
// or deserialization fail.
//
// Returns:
//   - error: Any error encountered during recovery (e.g., file access or JSON parsing errors).
func (b *Bus) RecoverSpillover() error {
	if b.spillover == nil {
		return nil
	}
	// Only the on-disk handler has a directory to read from.
	sh, ok := b.spillover.(*spilloverHandler)
	if !ok {
		// In-memory or custom handler: nothing to recover from disk.
		return nil
	}
	spillFilePath := filepath.Join(sh.dir, "spillover.log")
	log.Printf("audit.Bus: Starting spillover recovery from %s", spillFilePath)

	f, err := os.Open(spillFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("audit.Bus: Spillover file does not exist, nothing to recover")
			return nil
		}
		return fmt.Errorf("opening spillover file: %w", err)
	}
	scanner := bufio.NewScanner(f)
	var evts []Event
	for scanner.Scan() {
		var be BasicEvent
		if err := json.Unmarshal(scanner.Bytes(), &be); err != nil {
			log.Printf("audit.Bus: skipping invalid spill line: %v", err)
			continue
		}
		evts = append(evts, &be)
	}
	if err := scanner.Err(); err != nil {
		f.Close()
		return fmt.Errorf("reading spillover file: %w", err)
	}
	f.Close()

	if len(evts) == 0 {
		// Make sure the file is empty for next time.
		_ = os.Truncate(spillFilePath, 0)
		log.Printf("audit.Bus: no events to recover, truncated %s", spillFilePath)
		return nil
	}

	// Truncate before replay.
	if err := os.Truncate(spillFilePath, 0); err != nil {
		return fmt.Errorf("truncating spillover file: %w", err)
	}

	for i, evt := range evts {
		log.Printf("audit.Bus: Recovering spill event %d: %s", i+1, evt.ID())
		b.PublishSync(evt)
	}
	log.Printf("audit.Bus: Finished recovering %d events", len(evts))
	return nil
}

// RecoverSpilloverNow triggers immediate spillover recovery.
// It calls `RecoverSpillover` to process any spilled events immediately, but only if the bus
// is not closed. If the bus is closed, an error is returned.
//
// Returns:
//   - error: Any error from recovery or if the bus is closed.
func (b *Bus) RecoverSpilloverNow() error {
	if b.closed.Load() {
		return fmt.Errorf("bus closed")
	}
	return b.RecoverSpillover()
}

// spilloverHandler manages disk-based event spillover.
// It persists events to a file in the specified directory, ensuring thread-safe writes
// and proper resource cleanup. The handler is used when events cannot be processed
// immediately due to rate limits or queue capacity.
type spilloverHandler struct {
	dir  string        // Directory where the spillover file is stored.
	file *os.File      // File handle for the spillover log.
	mu   sync.Mutex    // Protects file writes for thread safety.
}

// newSpilloverHandler creates a new disk-based spillover handler.
// It creates the specified directory if it doesn't exist and opens a spillover log file
// for appending events. Errors are returned if directory creation or file opening fails.
//
// Parameters:
//   - dir: The directory to store the spillover log file.
//
// Returns:
//   - *spilloverHandler: A pointer to the initialized handler.
//   - error: Any error encountered during initialization.
func newSpilloverHandler(dir string) (*spilloverHandler, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create spillover directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "spillover.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open spillover file: %w", err)
	}
	return &spilloverHandler{dir: dir, file: f}, nil
}

// Write persists an event to the spillover file.
// It serializes the event to JSON and writes it to the file with a newline separator.
// The write operation is thread-safe, and the file is synced to ensure durability.
// Errors are returned if serialization or file operations fail.
//
// Parameters:
//   - evt: The event to write.
//
// Returns:
//   - error: Any error encountered during the write operation.
func (h *spilloverHandler) Write(evt Event) error {
	if h.file == nil {
		return fmt.Errorf("spillover file closed")
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	// Build a struct matching BasicEvent for JSON serialization.
	rec := struct {
		IDVal        string      `json:"IDVal"`
		TypeVal      EventType   `json:"TypeVal"`
		TimeVal      time.Time   `json:"TimeVal"`
		SourceVal    string      `json:"SourceVal"`
		ContextIDVal string      `json:"ContextIDVal"`
		PayloadVal   interface{} `json:"PayloadVal"`
	}{
		IDVal:        evt.ID(),
		TypeVal:      evt.Type(),
		TimeVal:      evt.Time(),
		SourceVal:    evt.Source(),
		ContextIDVal: evt.ContextID(),
		PayloadVal:   evt.Payload(),
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal spillover event: %w", err)
	}
	if _, err := h.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}
	return h.file.Sync()
}

// Close closes the spillover file.
// It releases the file handle and ensures thread safety. The method is idempotent,
// and subsequent calls return nil if the file is already closed.
//
// Returns:
//   - error: Any error encountered during the close operation.
func (h *spilloverHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file == nil {
		return nil
	}
	if err := h.file.Close(); err != nil {
		return fmt.Errorf("failed to close spillover file: %w", err)
	}
	h.file = nil
	return nil
}

// circuitBreaker manages failure states to prevent cascading failures.
// It tracks the number of handler failures and opens the circuit if the threshold
// is exceeded, preventing further processing until a timeout period elapses.
type circuitBreaker struct {
	mu         sync.Mutex    // Protects state and counters for thread safety.
	state      int32         // Circuit state (0 = closed, 1 = open).
	fails      int           // Number of consecutive failures.
	maxFails   int           // Maximum failures before opening the circuit.
	timeout    time.Duration // Duration before resetting the circuit.
	lastFail   time.Time     // Timestamp of the last failure.
}

// newCircuitBreaker creates a new circuit breaker with the specified timeout and failure threshold.
// It initializes the circuit in the closed state, ready to track failures.
//
// Parameters:
//   - timeout: Duration before the circuit resets after opening.
//   - maxFails: Maximum number of failures before opening the circuit.
//
// Returns:
//   - *circuitBreaker: A pointer to the initialized circuit breaker.
func newCircuitBreaker(timeout time.Duration, maxFails int) *circuitBreaker {
	return &circuitBreaker{
		state:    0,
		maxFails: maxFails,
		timeout:  timeout,
	}
}

// IsClosed checks if the circuit breaker is in the closed state.
// If the circuit is open and the timeout has elapsed, it resets to closed.
// The method is thread-safe.
//
// Returns:
//   - bool: True if the circuit is closed, false if open.
func (cb *circuitBreaker) IsClosed() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if atomic.LoadInt32(&cb.state) == 1 {
		if time.Since(cb.lastFail) > cb.timeout {
			atomic.StoreInt32(&cb.state, 0)
			cb.fails = 0
		}
	}
	return atomic.LoadInt32(&cb.state) == 0
}

// RecordFailure records a handler failure.
// It increments the failure count and opens the circuit if the threshold is reached.
// The method is thread-safe.
func (cb *circuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.fails++
	cb.lastFail = time.Now()
	if cb.fails >= cb.maxFails {
		atomic.StoreInt32(&cb.state, 1)
	}
}

// RecordSuccess records a successful handler execution.
// It resets the failure count if the circuit is closed. The method is thread-safe.
func (cb *circuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if atomic.LoadInt32(&cb.state) == 0 {
		cb.fails = 0
	}
}

// ensureID ensures an event has a unique ID.
// If the event's ID is empty, it wraps the event with an idEvent that provides a new UUID.
// This function is internal and not exported.
//
// Parameters:
//   - evt: The event to check.
//
// Returns:
//   - Event: The original event or a wrapped event with a new ID.
func ensureID(evt Event) Event {
	if evt.ID() == "" {
		return &idEvent{Event: evt, id: uuid.New().String()}
	}
	return evt
}

// idEvent wraps an Event to provide a unique ID.
// It is used internally to ensure events have a valid ID.
type idEvent struct {
	Event // The wrapped event.
	id    string // The unique ID for the event.
}

// ID returns the unique ID for the idEvent.
func (e *idEvent) ID() string {
	return e.id
}

// ensureTime ensures an event has a valid timestamp.
// If the event's timestamp is zero, it wraps the event with a timeEvent that provides
// the current time. This function is internal and not exported.
//
// Parameters:
//   - evt: The event to check.
//
// Returns:
//   - Event: The original event or a wrapped event with a timestamp.
func ensureTime(evt Event) Event {
	if evt.Time().IsZero() {
		return &timeEvent{Event: evt, t: time.Now()}
	}
	return evt
}

// timeEvent wraps an Event to provide a timestamp.
// It is used internally to ensure events have a valid timestamp.
type timeEvent struct {
	Event // The wrapped event.
	t     time.Time // The timestamp for the event.
}

// Time returns the timestamp for the timeEvent.
func (e *timeEvent) Time() time.Time {
	return e.t
}

// ensureSpanContext ensures an event has a valid span context.
// If the event's span context is invalid, it wraps the event with a spanEvent that provides
// a default span context from the background context. This function is internal and not exported.
//
// Parameters:
//   - evt: The event to check.
//
// Returns:
//   - Event: The original event or a wrapped event with a span context.
func ensureSpanContext(evt Event) Event {
	if !evt.SpanContext().IsValid() {
		return &spanEvent{Event: evt, spanCtx: trace.SpanContextFromContext(context.Background())}
	}
	return evt
}

// spanEvent wraps an Event to provide a span context.
// It is used internally to ensure events have a valid span context for tracing.
type spanEvent struct {
	Event   // The wrapped event.
	spanCtx trace.SpanContext // The span context for the event.
}

// SpanContext returns the span context for the spanEvent.
func (e *spanEvent) SpanContext() trace.SpanContext {
	return e.spanCtx
}

// estimateEventSize estimates the memory size of an event.
// It calculates an approximate size based on the event's ID, source, context ID,
// and payload (if it is a map). This is used to enforce memory limits for event history.
// This function is internal and not exported.
//
// Parameters:
//   - evt: The event to estimate.
//
// Returns:
//   - int64: The estimated memory size in bytes.
func estimateEventSize(evt Event) int64 {
	var size int64 = 100
	size += int64(len(evt.ID()) + len(evt.Source()) + len(evt.ContextID()))
	if pl, ok := evt.Payload().(map[string]interface{}); ok {
		for k, v := range pl {
			size += int64(len(k))
			switch v := v.(type) {
			case string:
				size += int64(len(v))
			case int, int64, float64, bool:
				size += 8
			}
		}
	}
	return size
}
