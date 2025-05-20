package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log" // Using standard log for internal handler errors, not audit events themselves
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"go.opentelemetry.io/otel/trace"
)

// Logging Event Types and Payloads

// Logging Event Types define standard audit event categories specifically for application logging.
// These types allow for consistent categorization and processing of log-related audit events.
const (
	// EventTypeLogInfo represents an informational log event.
	EventTypeLogInfo EventType = "log_info"
	// EventTypeLogWarning represents a warning log event, indicating potential issues.
	EventTypeLogWarning EventType = "log_warning"
	// EventTypeLogDebug represents a debug log event, typically used for detailed
	// diagnostic information in development or troubleshooting.
	EventTypeLogDebug EventType = "log_debug"
	// EventTypeLogError represents an error log event, indicating a failure or problem.
	EventTypeLogError EventType = "log_error"
	// EventTypeLogFatal represents a fatal log event, indicating a critical error
	// that typically leads to application termination.
	EventTypeLogFatal EventType = "log_fatal"
	// EventTypeLogAssertionFailed represents an event where an internal assertion failed.
	EventTypeLogAssertionFailed EventType = "log_assertion_failed"
)

// LogPayload is the structured payload for logging events.
// It encapsulates common fields for various log levels, allowing for rich,
// queryable log data within audit events.
type LogPayload struct {
	Message string            `json:"message"`         // The primary log message.
	Fields  map[string]string `json:"fields,omitempty"`// Optional key-value pairs for additional context.
	Error   string            `json:"error,omitempty"` // The string representation of an error, primarily for error and fatal events.
	Detail  string            `json:"detail,omitempty"`// Additional detail for assertion failed events.
}

// Database Utilities

// SetupDatabase initializes the audit table and its necessary indexes in the provided SQL database.
// It creates the `audit` table if it does not already exist, ensuring the schema
// is prepared for storing audit events. It also creates indexes on `context_id` and `time`
// for efficient querying.
//
// Parameters:
//   - db: An initialized `*sql.DB` connection pool to the database.
//
// Returns:
//   - error: An error if table or index creation fails.
func SetupDatabase(db *sql.DB) error {
	// Create the audit table if it doesn't exist.
	// `id` is a UUID, `type` for event category, `time` for timestamp,
	// `source` for origin, `context_id` for tracing/correlation, and `payload` for JSON data.
	createTableQuery := `
CREATE TABLE IF NOT EXISTS audit (
	id VARCHAR(36) PRIMARY KEY,
	type VARCHAR(255) NOT NULL,
	time TIMESTAMP NOT NULL,
	source VARCHAR(255) NOT NULL,
	context_id VARCHAR(255),
	payload TEXT NOT NULL
)`
	_, err := db.Exec(createTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create audit table: %w", err)
	}

	// Create an index on `context_id` for efficient lookup of events related to a specific context.
	createContextIndexQuery := `
CREATE INDEX IF NOT EXISTS idx_context_id ON audit (context_id);`
	_, err = db.Exec(createContextIndexQuery)
	if err != nil {
		return fmt.Errorf("failed to create context_id index: %w", err)
	}

	// Create an index on `time` for efficient time-series querying of events.
	createTimeIndexQuery := `
CREATE INDEX IF NOT EXISTS idx_time ON audit (time);`
	_, err = db.Exec(createTimeIndexQuery)
	if err != nil {
		return fmt.Errorf("failed to create time index: %w", err)
	}

	return nil
}

// init registers the schema definitions for all standard logging event types.
// This ensures that when events of these types are created or validated,
// their expected payload structure (required fields and field types) is known.
// This function is automatically called when the package is imported.
func init() {
	// Register schema for informational log events.
	RegisterSchema(EventTypeLogInfo, EventSchema{
		RequiredFields: []string{"message"}, // 'message' is always required.
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}), // 'fields' is optional but its type is defined.
		},
	})
	// Register schema for warning log events.
	RegisterSchema(EventTypeLogWarning, EventSchema{
		RequiredFields: []string{"message"},
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}),
		},
	})
	// Register schema for debug log events.
	RegisterSchema(EventTypeLogDebug, EventSchema{
		RequiredFields: []string{"message"},
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}),
		},
	})
	// Register schema for error log events.
	RegisterSchema(EventTypeLogError, EventSchema{
		RequiredFields: []string{"message", "error"}, // 'message' and 'error' are required.
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"error":   reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}),
		},
	})
	// Register schema for fatal log events.
	RegisterSchema(EventTypeLogFatal, EventSchema{
		RequiredFields: []string{"message"},
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}),
		},
	})
	// Register schema for assertion failed log events.
	RegisterSchema(EventTypeLogAssertionFailed, EventSchema{
		RequiredFields: []string{"message", "detail"}, // 'message' and 'detail' are required.
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"detail":  reflect.TypeOf(""),
		},
	})
}

// Event Creation Helpers for Logging

// NewInfo creates a new audit Event representing an informational log entry.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: A string identifying the origin of the event (e.g., "auth_service", "user_signup_flow").
//   - message: The main informational message.
//   - fields: Optional map of additional key-value pairs for context.
//
// Returns:
//   - Event: A new audit event of type `EventTypeLogInfo`.
func NewInfo(ctx context.Context, source, message string, fields map[string]string) Event {
	spanCtx := trace.SpanContextFromContext(ctx) // Extract OpenTelemetry SpanContext if available.
	return NewBasicEvent(
		EventTypeLogInfo,
		source,
		ContextIDFrom(ctx), // Extract contextual ID (e.g., request ID) from context.
		map[string]interface{}{"message": message, "fields": fields}, // Payload structured as a map.
		spanCtx,
	)
}

// NewWarning creates a new audit Event representing a warning log entry.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: A string identifying the origin of the event.
//   - message: The warning message.
//   - fields: Optional map of additional key-value pairs for context.
//
// Returns:
//   - Event: A new audit event of type `EventTypeLogWarning`.
func NewWarning(ctx context.Context, source, message string, fields map[string]string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeLogWarning,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"message": message, "fields": fields},
		spanCtx,
	)
}

// NewDebug creates a new audit Event representing a debug log entry.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: A string identifying the origin of the event.
//   - message: The debug message.
//   - fields: Optional map of additional key-value pairs for context.
//
// Returns:
//   - Event: A new audit event of type `EventTypeLogDebug`.
func NewDebug(ctx context.Context, source, message string, fields map[string]string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeLogDebug,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"message": message, "fields": fields},
		spanCtx,
	)
}

// NewError creates a new audit Event representing an error log entry.
// The payload includes the error message.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: A string identifying the origin of the event.
//   - message: A descriptive error message.
//   - err: The actual error object, whose string representation will be included in the payload.
//   - fields: Optional map of additional key-value pairs for context.
//
// Returns:
//   - Event: A new audit event of type `EventTypeLogError`.
func NewError(ctx context.Context, source, message string, err error, fields map[string]string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeLogError,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"message": message, "error": err.Error(), "fields": fields},
		spanCtx,
	)
}

// NewFatal creates a new audit Event representing a fatal log entry.
// This event typically precedes an application shutdown.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: A string identifying the origin of the event.
//   - message: The fatal error message.
//   - fields: Optional map of additional key-value pairs for context.
//
// Returns:
//   - Event: A new audit event of type `EventTypeLogFatal`.
func NewFatal(ctx context.Context, source, message string, fields map[string]string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeLogFatal,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"message": message, "fields": fields},
		spanCtx,
	)
}

// NewAssertionFailed creates a new audit Event representing an assertion failure.
// This is typically used in situations where a critical assumption in the code
// proves false, often leading to a panic.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: A string identifying the origin of the event.
//   - message: A brief description of the assertion that failed.
//   - detail: More detailed information about the failure, e.g., expected vs. got values.
//
// Returns:
//   - Event: A new audit event of type `EventTypeLogAssertionFailed`.
func NewAssertionFailed(ctx context.Context, source, message, detail string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeLogAssertionFailed,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"message": message, "detail": detail},
		spanCtx,
	)
}

// Logging Configuration and Setup

// LogConfig holds configuration parameters for audit event persistence handlers,
// specifically for file-based logging (via lumberjack) and database insertion.
type LogConfig struct {
	// FilePath is the path to the log file for audit events. An empty string
	// disables file logging.
	FilePath string
	// MaxSizeMB is the maximum size in megabytes of a log file before it is rotated.
	MaxSizeMB int
	// MaxBackups is the maximum number of old log files to retain.
	MaxBackups int
	// MaxAgeDays is the maximum number of days to retain old log files.
	MaxAgeDays int
	// Compress enables or disables compression of rotated log files.
	Compress bool
	// DBBatchSize is the number of events to batch together before attempting
	// a single database insertion.
	DBBatchSize int
	// FlushInterval is the maximum time to wait before flushing any accumulated
	// events to the database, even if `DBBatchSize` is not reached.
	FlushInterval time.Duration
	// RetryCount is the number of times to retry a failed database batch insert.
	RetryCount int
	// RetryDelay is the initial delay duration between retry attempts for database inserts.
	RetryDelay time.Duration
}

// DefaultLogConfig returns a LogConfig struct populated with default values.
// This provides a sensible starting point for configuring audit logging.
func DefaultLogConfig() LogConfig {
	return LogConfig{
		FilePath:      "",                   // No file logging by default
		MaxSizeMB:     100,                  // 100 MB per file
		MaxBackups:    3,                    // Keep 3 old compressed log files
		MaxAgeDays:    28,                   // Keep logs for 28 days
		Compress:      true,                 // Compress old log files
		DBBatchSize:   100,                  // Batch 100 events for DB inserts
		FlushInterval: 5 * time.Second,      // Flush DB batch every 5 seconds
		RetryCount:    3,                    // Retry DB inserts 3 times
		RetryDelay:    500 * time.Millisecond, // 500ms initial delay for DB retries
	}
}

// SetupLogging configures and registers audit event handlers for file and/or database persistence.
// It applies the provided `LogOption`s to a default configuration and then initializes
// the necessary handlers.
//
// It subscribes handlers to the main `Bus` for `EventAny` type, meaning they will receive
// all audit events.
//
// Parameters:
//   - bus: The main `*Bus` instance to which the handlers will subscribe.
//   - db: An optional `*sql.DB` connection pool. If nil, database logging is disabled.
//   - opts: Variadic functional options to customize the logging configuration.
//
// Returns:
//   - []func() error: A slice of cleanup functions (closers) that should be called
//     during application shutdown to gracefully close logging resources.
//   - error: An error if any handler fails to initialize (e.g., file logger setup).
func SetupLogging(bus *Bus, db *sql.DB, opts ...LogOption) ([]func() error, error) {
	cfg := DefaultLogConfig()
	for _, opt := range opts {
		opt(&cfg) // Apply all provided options to override defaults
	}

	var closers []func() error // Collect functions to be called during shutdown

	// Configure and subscribe the file handler if a file path is provided.
	if cfg.FilePath != "" {
		fh, err := newFileHandler(cfg, bus.metrics)
		if err != nil {
			return nil, fmt.Errorf("audit: file logger setup failed: %w", err)
		}
		bus.Subscribe(EventAny, fh.Handle) // Subscribe file handler to all events
		closers = append(closers, fh.Close) // Add file handler's close function to closers
	}

	// Configure and subscribe the database handler if a database connection is provided.
	if db != nil {
		dbHandler, closeDBHandler := createDBHandler(db, cfg, bus.metrics)
		bus.Subscribe(EventAny, dbHandler)   // Subscribe DB handler to all events
		closers = append(closers, closeDBHandler) // Add DB handler's close function to closers
	}

	return closers, nil
}

// LogOption is a functional option for configuring a LogConfig.
// These options provide a flexible way to modify logging behavior.
type LogOption func(*LogConfig)

// WithFilePath sets the file path for audit logs.
// If an empty string is provided, file logging will be disabled.
func WithFilePath(path string) LogOption {
	return func(cfg *LogConfig) {
		cfg.FilePath = path
	}
}

// WithMaxSizeMB sets the maximum size (in megabytes) a log file can reach
// before it's rotated.
func WithMaxSizeMB(size int) LogOption {
	return func(cfg *LogConfig) {
		cfg.MaxSizeMB = size
	}
}

// WithMaxBackups sets the maximum number of old log files to retain after rotation.
func WithMaxBackups(backups int) LogOption {
	return func(cfg *LogConfig) {
		cfg.MaxBackups = backups
	}
}

// WithMaxAgeDays sets the maximum number of days to retain old log files.
// Files older than this age will be purged during rotation.
func WithMaxAgeDays(days int) LogOption {
	return func(cfg *LogConfig) {
		cfg.MaxAgeDays = days
	}
}

// WithCompress enables or disables compression (gzip) of rotated log files.
func WithCompress(compress bool) LogOption {
	return func(cfg *LogConfig) {
		cfg.Compress = compress
	}
}

// WithDBBatchSize sets the number of audit events to accumulate in a batch
// before attempting a single bulk insert into the database.
func WithDBBatchSize(size int) LogOption {
	return func(cfg *LogConfig) {
		cfg.DBBatchSize = size
	}
}

// WithFlushInterval sets the maximum time between database flushes.
// Even if `DBBatchSize` is not met, accumulated events will be flushed
// after this interval.
func WithFlushInterval(interval time.Duration) LogOption {
	return func(cfg *LogConfig) {
		cfg.FlushInterval = interval
	}
}

// WithRetryCount sets the number of retries for database batch insert operations.
func WithRetryCount(count int) LogOption {
	return func(cfg *LogConfig) {
		cfg.RetryCount = count
	}
}

// WithRetryDelay sets the initial delay duration before retrying a failed
// database batch insert. Subsequent retries may use an exponential backoff strategy
// based on this initial delay.
func WithRetryDelay(delay time.Duration) LogOption {
	return func(cfg *LogConfig) {
		cfg.RetryDelay = delay
	}
}

// Internal Log Handlers

// fileHandler is an internal handler responsible for writing audit events to a file.
// It uses `lumberjack.Logger` for log rotation and compression.
type fileHandler struct {
	logger  *lumberjack.Logger // The logger responsible for file writing and rotation.
	mu      sync.Mutex         // Mutex to protect access to the logger for concurrent writes.
	metrics BusMetrics         // Interface for reporting metrics related to file handler operations.
}

// newFileHandler creates and initializes a `fileHandler` based on the provided LogConfig.
// It sets up `lumberjack.Logger` with the specified file path, size, backup, age, and compression settings.
//
// Parameters:
//   - cfg: The LogConfig containing file logging parameters.
//   - metrics: The BusMetrics instance to report handler latency and dropped events.
//
// Returns:
//   - *fileHandler: A pointer to the newly created fileHandler.
//   - error: An error if the logger cannot be initialized (though lumberjack typically
//     doesn't return errors on initialization, rather on write).
func newFileHandler(cfg LogConfig, metrics BusMetrics) (*fileHandler, error) {
	logger := &lumberjack.Logger{
		Filename:   cfg.FilePath,
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   cfg.Compress,
	}
	return &fileHandler{
		logger:  logger,
		metrics: metrics,
	}, nil
}

// Handle processes an audit event by marshaling it to JSON and writing it to the configured log file.
// It sanitizes the event payload before marshaling to ensure sensitive data is not logged.
// File writes are synchronized using a mutex. Metrics for handler latency and dropped events are recorded.
//
// Parameters:
//   - evt: The audit Event to be handled.
//
// Returns:
//   - error: An error if the payload cannot be marshaled or if writing to the file fails.
func (h *fileHandler) Handle(evt Event) error {
	start := time.Now()
	h.mu.Lock() // Ensure only one goroutine writes to the file at a time
	defer h.mu.Unlock()

	// Sanitize the event payload to remove sensitive information before logging.
	sanitizedEvt := SanitizePayload(evt)
	payload, ok := sanitizedEvt.Payload().(map[string]interface{})
	if !ok {
		h.metrics.EventDropped(evt.Type())
		return fmt.Errorf("audit: fileHandler received invalid payload type %T for event type %s", sanitizedEvt.Payload(), evt.Type())
	}

	// Prepare the log record structure for JSON marshaling.
	record := map[string]interface{}{
		"id":         evt.ID(),
		"type":       string(evt.Type()),
		"time":       evt.Time().Format(time.RFC3339Nano), // Format time consistently
		"source":     evt.Source(),
		"context_id": evt.ContextID(),
		"payload":    payload,
	}

	data, err := json.Marshal(record)
	if err != nil {
		h.metrics.EventDropped(evt.Type())
		return fmt.Errorf("audit: fileHandler failed to marshal event record: %w", err)
	}

	// Write the JSON data followed by a newline.
	_, err = h.logger.Write(append(data, '\n'))
	if err != nil {
		h.metrics.EventDropped(evt.Type())
		return fmt.Errorf("audit: fileHandler failed to write to log file: %w", err)
	}

	h.metrics.HandlerLatency(evt.Type(), time.Since(start)) // Record how long handling took
	return nil
}

// Close gracefully shuts down the fileHandler by closing the underlying `lumberjack.Logger`.
// This ensures that all buffered writes are flushed to disk and file resources are released.
// The method is synchronized to prevent concurrent access during shutdown.
//
// Returns:
//   - error: An error if the logger fails to close.
func (h *fileHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.logger.Close()
}

// createDBHandler sets up a background goroutine for batching and inserting audit events
// into the database. It returns a `Handler` function that can be subscribed to the audit bus,
// and a `closer` function that should be called to gracefully shut down the database handler.
//
// Events are buffered in a channel and periodically flushed to the database
// either when the batch size is reached or after a specific flush interval.
// Database inserts include retry logic.
//
// Parameters:
//   - db: The `*sql.DB` connection pool for database operations.
//   - cfg: The LogConfig containing database logging parameters (batch size, flush interval, retries).
//   - metrics: The BusMetrics instance to report handler latency and dropped events.
//
// Returns:
//   - Handler: A function conforming to the `Handler` interface, to be subscribed to the audit bus.
//   - func() error: A cleanup function to close the database handler's goroutine.
func createDBHandler(db *sql.DB, cfg LogConfig, metrics BusMetrics) (Handler, func() error) {
	// `events` channel buffers incoming audit events before batching.
	events := make(chan Event, cfg.DBBatchSize)
	// `closed` channel signals the background goroutine to shut down.
	closed := make(chan struct{})
	var wg sync.WaitGroup // WaitGroup to ensure the goroutine finishes before `closer` returns.

	wg.Add(1) // Increment counter for the background goroutine
	go func() {
		defer wg.Done() // Decrement counter when goroutine exits
		var batch []Event // Buffer for events to be inserted in a single transaction.
		// Ticker for periodic flushing of events to the database.
		ticker := time.NewTicker(cfg.FlushInterval)
		defer ticker.Stop() // Ensure ticker is stopped to release resources.

		for {
			select {
			case evt, ok := <-events: // Event received from the bus.
				if !ok { // Channel was closed (signal to shut down).
					// If there are remaining events in the batch, attempt a final insert.
					if len(batch) > 0 {
						if err := insertBatch(db, batch, cfg, metrics); err != nil {
							log.Printf("audit: db batch insert failed during shutdown: %v", err)
						}
					}
					return // Exit goroutine.
				}
				batch = append(batch, evt)
				// If batch size is reached, flush the batch.
				if len(batch) >= cfg.DBBatchSize {
					if err := insertBatch(db, batch, cfg, metrics); err != nil {
						log.Printf("audit: db batch insert failed: %v", err)
					}
					batch = nil // Clear the batch after insertion.
				}
			case <-ticker.C: // Flush interval reached.
				if len(batch) > 0 { // If there are events, flush them.
					if err := insertBatch(db, batch, cfg, metrics); err != nil {
						log.Printf("audit: db batch insert failed: %v", err)
					}
					batch = nil // Clear the batch after insertion.
				}
			case <-closed: // Explicit close signal received.
				// Perform final flush of any remaining events.
				if len(batch) > 0 {
					if err := insertBatch(db, batch, cfg, metrics); err != nil {
						log.Printf("audit: db batch insert failed during explicit close: %v", err)
					}
				}
				return // Exit goroutine.
			}
		}
	}()

	// The `handler` function is what the audit bus will call to send events.
	// It simply sends events to the internal `events` channel.
	handler := func(evt Event) error {
		select {
		case events <- evt: // Attempt to send event to the channel.
			return nil
		case <-closed: // If the handler is closing, reject new events.
			return fmt.Errorf("audit: db handler closed, cannot accept new events")
		default: // If channel is full, drop the event.
			// Note: Metrics for dropped events due to full queue are usually handled
			// at the Bus level. Here, we just indicate a failure.
			return fmt.Errorf("audit: db handler queue full, event dropped")
		}
	}

	// The `closer` function signals the background goroutine to stop and waits for it to finish.
	closer := func() error {
		close(closed) // Signal background goroutine to stop.
		wg.Wait()     // Wait for the goroutine to finish its work and exit.
		return nil
	}

	return handler, closer
}

// insertBatch attempts to insert a batch of audit events into the database within a single transaction.
// It includes retry logic with exponential backoff for transient database errors.
//
// Each event's payload is marshaled to JSON. Events that fail to marshal or execute
// individually will be logged as errors and their metrics dropped, but the batch
// will continue if possible. The entire transaction is committed only if all events
// are prepared and executed without critical errors.
//
// Parameters:
//   - db: The `*sql.DB` connection pool.
//   - events: A slice of `Event` objects to be inserted.
//   - cfg: The `LogConfig` containing retry parameters.
//   - metrics: The `BusMetrics` instance for reporting latency and dropped events.
//
// Returns:
//   - error: An error if the batch insertion fails after all retries.
func insertBatch(db *sql.DB, events []Event, cfg LogConfig, metrics BusMetrics) error {
	const query = `
INSERT INTO audit (id, type, time, source, context_id, payload)
VALUES (?, ?, ?, ?, ?, ?)`

	// Record start time for batch latency metric.
	start := time.Now()

	// Loop for retry attempts.
	for attempt := 1; attempt <= cfg.RetryCount; attempt++ {
		tx, err := db.Begin() // Start a new transaction for the batch.
		if err != nil {
			log.Printf("audit: db batch: attempt %d: failed to begin transaction: %v", attempt, err)
			time.Sleep(cfg.RetryDelay) // Wait before retrying.
			continue
		}

		stmt, err := tx.Prepare(query) // Prepare the SQL statement within the transaction.
		if err != nil {
			tx.Rollback() // Rollback on prepare error.
			log.Printf("audit: db batch: attempt %d: failed to prepare statement: %v", attempt, err)
			time.Sleep(cfg.RetryDelay)
			continue
		}

		success := true // Flag to track if all events in this attempt were successfully prepared/executed.
		for _, evt := range events {
			payload, err := json.Marshal(evt.Payload()) // Marshal event payload to JSON.
			if err != nil {
				log.Printf("audit: db batch: failed to marshal event payload for event ID %s: %v", evt.ID(), err)
				metrics.EventDropped(evt.Type()) // Increment dropped metric for this specific event.
				success = false                  // Mark the batch as having encountered an internal event failure.
				continue                         // Skip this event, try the next one in the batch.
			}

			// Execute the prepared statement for each event.
			_, err = stmt.Exec(
				evt.ID(),
				string(evt.Type()),
				evt.Time().Format(time.RFC3339Nano), // Format time for database consistency.
				evt.Source(),
				evt.ContextID(),
				string(payload),
			)
			if err != nil {
				log.Printf("audit: db batch: failed to execute statement for event ID %s: %v", evt.ID(), err)
				metrics.EventDropped(evt.Type()) // Increment dropped metric for this specific event.
				success = false                  // Mark the batch as having encountered an internal event failure.
				continue                         // Skip this event, try the next one in the batch.
			}
		}
		stmt.Close() // Close the statement after iterating through all events.

		if success { // If all individual events were processed without non-recoverable errors...
			err = tx.Commit() // Attempt to commit the transaction.
			if err == nil {
				// If commit is successful, record the latency for the entire batch.
				// We use the first event's type as a representative label for the batch.
				if len(events) > 0 {
					metrics.HandlerLatency(events[0].Type(), time.Since(start))
				}
				return nil // Batch committed successfully.
			}
			// If commit fails, log the error and let the retry logic handle it.
			log.Printf("audit: db batch: attempt %d: failed to commit transaction: %v", attempt, err)
			tx.Rollback() // Rollback the transaction on commit failure.
		} else {
			// If there were any failures within the batch (e.g., marshaling errors for specific events),
			// rollback the entire transaction and retry the whole batch if more attempts are available.
			log.Printf("audit: db batch: attempt %d: contained failed events, rolling back transaction", attempt)
			tx.Rollback()
		}

		// If this wasn't the last attempt, wait before retrying.
		if attempt < cfg.RetryCount {
			time.Sleep(cfg.RetryDelay)
		}
	}

	// If control reaches here, all retry attempts have failed.
	// Log a final error message. Note that individual event drops were already
	// handled within the loop, so no collective drop metric is needed here.
	if len(events) > 0 {
		return fmt.Errorf("audit: db batch insert failed after %d attempts for batch starting with type %s", cfg.RetryCount, events[0].Type())
	}
	return fmt.Errorf("audit: db batch insert failed after %d attempts (empty batch)", cfg.RetryCount)
}

// High-Level Logger

// Logger provides a high-level, convenient API for common logging operations
// that publish events to the audit bus. It abstracts away the direct creation
// of `Event` objects and interaction with `Bus.Publish`.
type Logger struct {
	Bus     *Bus       // The underlying audit bus to which events are published.
	Metrics BusMetrics // The metrics interface for tracking logger operations.
}

// NewLogger creates a new Logger instance, integrating it with the provided audit Bus.
//
// Parameters:
//   - bus: The `*Bus` instance that the logger will use to publish events.
//
// Returns:
//   - *Logger: A pointer to the newly created Logger.
func NewLogger(bus *Bus) *Logger {
	return &Logger{
		Bus:     bus,
		Metrics: bus.metrics, // Access the Bus's internal metrics interface.
	}
}

// Info publishes an informational log event to the audit bus.
// The event is typically published asynchronously.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: The origin of the log message.
//   - message: The informational message.
//   - fields: Optional additional key-value pairs.
func (l *Logger) Info(ctx context.Context, source, message string, fields map[string]string) {
	start := time.Now()
	l.Bus.Publish(NewInfo(ctx, source, message, fields)) // Create and publish an info event.
	l.Metrics.HandlerLatency(EventTypeLogInfo, time.Since(start)) // Record publish latency.
}

// Warning publishes a warning log event to the audit bus.
// The event is typically published asynchronously.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: The origin of the log message.
//   - message: The warning message.
//   - fields: Optional additional key-value pairs.
func (l *Logger) Warning(ctx context.Context, source, message string, fields map[string]string) {
	start := time.Now()
	l.Bus.Publish(NewWarning(ctx, source, message, fields)) // Create and publish a warning event.
	l.Metrics.HandlerLatency(EventTypeLogWarning, time.Since(start)) // Record publish latency.
}

// Debug publishes a debug log event to the audit bus.
// The event is typically published asynchronously.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: The origin of the log message.
//   - message: The debug message.
//   - fields: Optional additional key-value pairs.
func (l *Logger) Debug(ctx context.Context, source, message string, fields map[string]string) {
	start := time.Now()
	l.Bus.Publish(NewDebug(ctx, source, message, fields)) // Create and publish a debug event.
	l.Metrics.HandlerLatency(EventTypeLogDebug, time.Since(start)) // Record publish latency.
}

// Error publishes an error log event to the audit bus.
// The event is typically published asynchronously.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: The origin of the log message.
//   - message: A descriptive error message.
//   - err: The actual error object.
//   - fields: Optional additional key-value pairs.
func (l *Logger) Error(ctx context.Context, source, message string, err error, fields map[string]string) {
	start := time.Now()
	l.Bus.Publish(NewError(ctx, source, message, err, fields)) // Create and publish an error event.
	l.Metrics.HandlerLatency(EventTypeLogError, time.Since(start)) // Record publish latency.
}

// Fatal publishes a fatal log event to the audit bus synchronously
// and then terminates the application process with exit code 1.
// This method blocks until the event is fully processed by handlers.
//
// Parameters:
//   - ctx: The context, potentially containing a trace ID or correlation ID.
//   - source: The origin of the log message.
//   - message: The fatal message.
//   - fields: Optional additional key-value pairs.
func (l *Logger) Fatal(ctx context.Context, source, message string, fields map[string]string) {
	start := time.Now()
	// Publish synchronously to ensure the fatal event is processed before exit.
	l.Bus.PublishSync(NewFatal(ctx, source, message, fields))
	l.Metrics.HandlerLatency(EventTypeLogFatal, time.Since(start)) // Record publish latency.
	os.Exit(1) // Terminate the application.
}

// AssertTrue checks if a given boolean condition is true. If false, it
// publishes a synchronous `EventTypeLogAssertionFailed` event to the audit bus
// and then panics with a descriptive message.
//
// Parameters:
//   - ctx: The context.
//   - source: The origin of the assertion.
//   - name: A name or description of the assertion (e.g., "UserExists").
//   - cond: The boolean condition to check.
func (l *Logger) AssertTrue(ctx context.Context, source, name string, cond bool) {
	if !cond {
		start := time.Now()
		evt := NewAssertionFailed(ctx, source, name, "expected true")
		// Publish synchronously to ensure assertion failure is logged before panic.
		l.Bus.PublishSync(evt)
		l.Metrics.HandlerLatency(EventTypeLogAssertionFailed, time.Since(start)) // Record publish latency.
		panic("assertion failed: " + name) // Panic to halt execution.
	}
}

// AssertNoError checks if a given error is nil. If the error is not nil, it
// publishes a synchronous `EventTypeLogAssertionFailed` event to the audit bus
// and then panics with the original error.
//
// Parameters:
//   - ctx: The context.
//   - source: The origin of the assertion.
//   - err: The error to check.
func (l *Logger) AssertNoError(ctx context.Context, source string, err error) {
	if err != nil {
		start := time.Now()
		evt := NewAssertionFailed(ctx, source, "NoError", err.Error())
		// Publish synchronously to ensure assertion failure is logged before panic.
		l.Bus.PublishSync(evt)
		l.Metrics.HandlerLatency(EventTypeLogAssertionFailed, time.Since(start)) // Record publish latency.
		panic(err) // Panic with the original error.
	}
}

// AssertEqual checks if two values are deeply equal using `reflect.DeepEqual`. If they are not equal, it
// publishes a synchronous `EventTypeLogAssertionFailed` event to the audit bus
// with details of the discrepancy and then panics.
//
// Parameters:
//   - ctx: The context.
//   - source: The origin of the assertion.
//   - name: A name or description of the assertion (e.g., "ConfigurationMatch").
//   - got: The value received.
//   - want: The value expected.
func (l *Logger) AssertEqual(ctx context.Context, source, name string, got, want interface{}) {
	if !reflect.DeepEqual(got, want) {
		start := time.Now()
		detail := fmt.Sprintf("expected=%v, got=%v", want, got)
		evt := NewAssertionFailed(ctx, source, name, detail)
		// Publish synchronously to ensure assertion failure is logged before panic.
		l.Bus.PublishSync(evt)
		l.Metrics.HandlerLatency(EventTypeLogAssertionFailed, time.Since(start)) // Record publish latency.
		panic("assertion failed: " + name + ": " + detail) // Panic with details of the mismatch.
	}
}