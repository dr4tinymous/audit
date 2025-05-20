package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"go.opentelemetry.io/otel/trace"
)

// Logging Event Types
const (
	EventTypeLogInfo            EventType = "log_info"
	EventTypeLogWarning         EventType = "log_warning"
	EventTypeLogDebug           EventType = "log_debug"
	EventTypeLogError           EventType = "log_error"
	EventTypeLogFatal           EventType = "log_fatal"
	EventTypeLogAssertionFailed EventType = "log_assertion_failed"
)

// LogPayload is the payload structure for logging events.
type LogPayload struct {
	Message string
	Fields  map[string]string
	Error   string // Only for error and fatal events
	Detail  string // Only for assertion failed events
}

// SetupDatabase initializes the audit table and indexes in the database.
func SetupDatabase(db *sql.DB) error {
	// Create the table first without inline index definitions
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

	// Create indexes separately using CREATE INDEX IF NOT EXISTS
	createContextIndexQuery := `
CREATE INDEX IF NOT EXISTS idx_context_id ON audit (context_id);`
	_, err = db.Exec(createContextIndexQuery)
	if err != nil {
		return fmt.Errorf("failed to create context_id index: %w", err)
	}

	createTimeIndexQuery := `
CREATE INDEX IF NOT EXISTS idx_time ON audit (time);`
	_, err = db.Exec(createTimeIndexQuery)
	if err != nil {
		return fmt.Errorf("failed to create time index: %w", err)
	}

	return nil
}

// init registers schemas for logging event types.
func init() {
	RegisterSchema(EventTypeLogInfo, EventSchema{
		RequiredFields: []string{"message"},
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}),
		},
	})
	RegisterSchema(EventTypeLogWarning, EventSchema{
		RequiredFields: []string{"message"},
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}),
		},
	})
	RegisterSchema(EventTypeLogDebug, EventSchema{
		RequiredFields: []string{"message"},
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}),
		},
	})
	RegisterSchema(EventTypeLogError, EventSchema{
		RequiredFields: []string{"message", "error"},
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"error":   reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}),
		},
	})
	RegisterSchema(EventTypeLogFatal, EventSchema{
		RequiredFields: []string{"message"},
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"fields":  reflect.TypeOf(map[string]string{}),
		},
	})
	RegisterSchema(EventTypeLogAssertionFailed, EventSchema{
		RequiredFields: []string{"message", "detail"},
		FieldTypes: map[string]reflect.Type{
			"message": reflect.TypeOf(""),
			"detail":  reflect.TypeOf(""),
		},
	})
}

// NewInfo creates an info-level logging event.
func NewInfo(ctx context.Context, source, message string, fields map[string]string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeLogInfo,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"message": message, "fields": fields},
		spanCtx,
	)
}

// NewWarning creates a warning-level logging event.
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

// NewDebug creates a debug-level logging event.
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

// NewError creates an error-level logging event.
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

// NewFatal creates a fatal-level logging event.
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

// NewAssertionFailed creates an assertion-failed logging event.
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

// LogConfig holds configuration for logging handlers.
type LogConfig struct {
	FilePath      string
	MaxSizeMB     int
	MaxBackups    int
	MaxAgeDays    int
	Compress      bool
	DBBatchSize   int
	FlushInterval time.Duration
	RetryCount    int
	RetryDelay    time.Duration
}

// DefaultLogConfig returns a default logging configuration.
func DefaultLogConfig() LogConfig {
	return LogConfig{
		FilePath:      "",
		MaxSizeMB:     100,
		MaxBackups:    3,
		MaxAgeDays:    28,
		Compress:      true,
		DBBatchSize:   100,
		FlushInterval: 5 * time.Second,
		RetryCount:    3,
		RetryDelay:    500 * time.Millisecond,
	}
}

// SetupLogging configures file and database persistence for audit events.
func SetupLogging(bus *Bus, db *sql.DB, opts ...LogOption) ([]func() error, error) {
	cfg := DefaultLogConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	var closers []func() error

	if cfg.FilePath != "" {
		fh, err := newFileHandler(cfg, bus.metrics)
		if err != nil {
			return nil, fmt.Errorf("audit: file logger setup failed: %w", err)
		}
		bus.Subscribe(EventAny, fh.Handle)
		closers = append(closers, fh.Close)
	}

	if db != nil {
		dbHandler, closeDBHandler := createDBHandler(db, cfg, bus.metrics)
		bus.Subscribe(EventAny, dbHandler)
		closers = append(closers, closeDBHandler)
	}

	return closers, nil
}

// LogOption is a functional option for configuring logging.
type LogOption func(*LogConfig)

func WithFilePath(path string) LogOption {
	return func(cfg *LogConfig) {
		cfg.FilePath = path
	}
}

func WithMaxSizeMB(size int) LogOption {
	return func(cfg *LogConfig) {
		cfg.MaxSizeMB = size
	}
}

func WithMaxBackups(backups int) LogOption {
	return func(cfg *LogConfig) {
		cfg.MaxBackups = backups
	}
}

func WithMaxAgeDays(days int) LogOption {
	return func(cfg *LogConfig) {
		cfg.MaxAgeDays = days
	}
}

func WithCompress(compress bool) LogOption {
	return func(cfg *LogConfig) {
		cfg.Compress = compress
	}
}

func WithDBBatchSize(size int) LogOption {
	return func(cfg *LogConfig) {
		cfg.DBBatchSize = size
	}
}

func WithFlushInterval(interval time.Duration) LogOption {
	return func(cfg *LogConfig) {
		cfg.FlushInterval = interval
	}
}

func WithRetryCount(count int) LogOption {
	return func(cfg *LogConfig) {
		cfg.RetryCount = count
	}
}

func WithRetryDelay(delay time.Duration) LogOption {
	return func(cfg *LogConfig) {
		cfg.RetryDelay = delay
	}
}

type fileHandler struct {
	logger  *lumberjack.Logger
	mu      sync.Mutex
	metrics BusMetrics
}

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

func (h *fileHandler) Handle(evt Event) error {
	start := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()

	sanitizedEvt := SanitizePayload(evt)
	payload, ok := sanitizedEvt.Payload().(map[string]interface{})
	if !ok {
		h.metrics.EventDropped(evt.Type())
		return fmt.Errorf("audit: fileHandler invalid payload type: %T", sanitizedEvt.Payload())
	}

	record := map[string]interface{}{
		"id":         evt.ID(),
		"type":       string(evt.Type()),
		"time":       evt.Time().Format(time.RFC3339Nano),
		"source":     evt.Source(),
		"context_id": evt.ContextID(),
		"payload":    payload,
	}

	data, err := json.Marshal(record)
	if err != nil {
		h.metrics.EventDropped(evt.Type())
		return fmt.Errorf("audit: fileHandler marshal: %w", err)
	}

	_, err = h.logger.Write(append(data, '\n'))
	if err != nil {
		h.metrics.EventDropped(evt.Type())
		return fmt.Errorf("audit: fileHandler write: %w", err)
	}

	h.metrics.HandlerLatency(evt.Type(), time.Since(start))
	return nil
}

func (h *fileHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.logger.Close()
}

func createDBHandler(db *sql.DB, cfg LogConfig, metrics BusMetrics) (Handler, func() error) {
	events := make(chan Event, cfg.DBBatchSize)
	closed := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		var batch []Event
		ticker := time.NewTicker(cfg.FlushInterval)
		defer ticker.Stop()

		for {
			select {
			case evt, ok := <-events:
				if !ok {
					if len(batch) > 0 {
						if err := insertBatch(db, batch, cfg, metrics); err != nil {
							log.Printf("audit: db batch insert failed: %v", err)
						}
					}
					return
				}
				batch = append(batch, evt)
				if len(batch) >= cfg.DBBatchSize {
					if err := insertBatch(db, batch, cfg, metrics); err != nil {
						log.Printf("audit: db batch insert failed: %v", err)
					}
					batch = nil
				}
			case <-ticker.C:
				if len(batch) > 0 {
					if err := insertBatch(db, batch, cfg, metrics); err != nil {
						log.Printf("audit: db batch insert failed: %v", err)
					}
					batch = nil
				}
			case <-closed:
				if len(batch) > 0 {
					if err := insertBatch(db, batch, cfg, metrics); err != nil {
						log.Printf("audit: db batch insert failed: %v", err)
					}
				}
				return
			}
		}
	}()

	handler := func(evt Event) error {
		select {
		case events <- evt:
			return nil
		case <-closed:
			return fmt.Errorf("audit: db handler closed")
		default:
			return fmt.Errorf("audit: db handler queue full")
		}
	}

	closer := func() error {
		close(closed)
		wg.Wait()
		return nil
	}

	return handler, closer
}

func insertBatch(db *sql.DB, events []Event, cfg LogConfig, metrics BusMetrics) error {
	const query = `
INSERT INTO audit (id, type, time, source, context_id, payload)
VALUES (?, ?, ?, ?, ?, ?)`

	start := time.Now()

	for attempt := 1; attempt <= cfg.RetryCount; attempt++ {
		tx, err := db.Begin()
		if err != nil {
			time.Sleep(cfg.RetryDelay)
			continue
		}

		stmt, err := tx.Prepare(query)
		if err != nil {
			tx.Rollback()
			time.Sleep(cfg.RetryDelay)
			continue
		}

		success := true // Flag to check if all events in the batch were prepared/executed successfully
		for _, evt := range events {
			payload, err := json.Marshal(evt.Payload())
			if err != nil {
				// Log the error but continue with the batch if possible
				log.Printf("audit: failed to marshal event payload for batch insert: %v", err)
				metrics.EventDropped(evt.Type()) // Consider dropping this specific event metric
				success = false // Mark batch as having a failure
				continue // Skip this event, try the next one in the batch
			}

			_, err = stmt.Exec(
				evt.ID(),
				string(evt.Type()),
				evt.Time().Format(time.RFC3339Nano),
				evt.Source(),
				evt.ContextID(),
				string(payload),
			)
			if err != nil {
				// Log the error but continue with the batch if possible
				log.Printf("audit: failed to execute statement for batch insert: %v", err)
				metrics.EventDropped(evt.Type()) // Consider dropping this specific event metric
				success = false // Mark batch as having a failure
				continue // Skip this event, try the next one in the batch
			}
		}
		stmt.Close() // Close the statement after the loop

		if success { // Only attempt commit if all events were processed without fatal errors
			err = tx.Commit()
			if err == nil {
				// If commit is successful, record latency for the batch (using the first event's type as a proxy)
				if len(events) > 0 {
					metrics.HandlerLatency(events[0].Type(), time.Since(start))
				}
				return nil // Batch committed successfully
			}
			// If commit fails, log and fall through to retry logic
			log.Printf("audit: db batch commit failed: %v", err)
			tx.Rollback() // Rollback the transaction
		} else {
             // If there were failures within the batch, rollback and potentially retry the whole batch
             log.Printf("audit: db batch contained failed events, rolling back transaction")
             tx.Rollback()
        }


		if attempt < cfg.RetryCount {
			time.Sleep(cfg.RetryDelay)
		}
	}

	// If we reach here, batch insertion failed after all retries.
	// Log a final error and potentially drop metrics for the entire batch.
	log.Printf("audit: db batch insert failed after %d attempts for batch starting with type %s", cfg.RetryCount, events[0].Type())
	// metrics.EventDropped(events[0].Type()) // Already handled for individual events during the loop
	return fmt.Errorf("audit: db batch insert failed after %d attempts", cfg.RetryCount)
}

type Logger struct {
	Bus     *Bus
	Metrics BusMetrics
}

func NewLogger(bus *Bus) *Logger {
	return &Logger{
		Bus:     bus,
		Metrics: bus.metrics,
	}
}

func (l *Logger) Info(ctx context.Context, source, message string, fields map[string]string) {
	start := time.Now()
	l.Bus.Publish(NewInfo(ctx, source, message, fields))
	l.Metrics.HandlerLatency(EventTypeLogInfo, time.Since(start))
}

func (l *Logger) Warning(ctx context.Context, source, message string, fields map[string]string) {
	start := time.Now()
	l.Bus.Publish(NewWarning(ctx, source, message, fields))
	l.Metrics.HandlerLatency(EventTypeLogWarning, time.Since(start))
}

func (l *Logger) Debug(ctx context.Context, source, message string, fields map[string]string) {
	start := time.Now()
	l.Bus.Publish(NewDebug(ctx, source, message, fields))
	l.Metrics.HandlerLatency(EventTypeLogDebug, time.Since(start))
}

func (l *Logger) Error(ctx context.Context, source, message string, err error, fields map[string]string) {
	start := time.Now()
	l.Bus.Publish(NewError(ctx, source, message, err, fields))
	l.Metrics.HandlerLatency(EventTypeLogError, time.Since(start))
}

func (l *Logger) Fatal(ctx context.Context, source, message string, fields map[string]string) {
	start := time.Now()
	l.Bus.PublishSync(NewFatal(ctx, source, message, fields))
	l.Metrics.HandlerLatency(EventTypeLogFatal, time.Since(start))
	os.Exit(1)
}

func (l *Logger) AssertTrue(ctx context.Context, source, name string, cond bool) {
	if !cond {
		start := time.Now()
		evt := NewAssertionFailed(ctx, source, name, "expected true")
		l.Bus.PublishSync(evt)
		l.Metrics.HandlerLatency(EventTypeLogAssertionFailed, time.Since(start))
		panic("assertion failed: " + name)
	}
}

func (l *Logger) AssertNoError(ctx context.Context, source string, err error) {
	if err != nil {
		start := time.Now()
		evt := NewAssertionFailed(ctx, source, "NoError", err.Error())
		l.Bus.PublishSync(evt)
		l.Metrics.HandlerLatency(EventTypeLogAssertionFailed, time.Since(start))
		panic(err)
	}
}

func (l *Logger) AssertEqual(ctx context.Context, source, name string, got, want interface{}) {
	if !reflect.DeepEqual(got, want) {
		start := time.Now()
		detail := fmt.Sprintf("expected=%v, got=%v", want, got)
		evt := NewAssertionFailed(ctx, source, name, detail)
		l.Bus.PublishSync(evt)
		l.Metrics.HandlerLatency(EventTypeLogAssertionFailed, time.Since(start))
		panic("assertion failed: " + name + ": " + detail)
	}
}