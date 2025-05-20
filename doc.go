// Package audit provides a robust, in-memory, publish-subscribe bus for managing and processing audit events.
// It is designed for high-throughput, low-latency event processing, incorporating features for resilience,
// observability, and data integrity. The package offers mechanisms for asynchronous event delivery,
// historical event storage, spillover to disk during backpressure, rate limiting, and circuit breaking.
//
// Core Concepts:
//
// The central component of this package is the `Bus` which facilitates the publish-subscribe pattern.
//
//   - Event: The `Event` interface represents a single auditable occurrence. It defines
//     methods to access common attributes such as `ID()`, `Type()`, `Time()`, `Source()`, `ContextID()`,
//     and `Payload()`. The `BasicEvent` struct provides a simple, concrete implementation of this interface.
//     Events also carry `SpanContext()` for distributed tracing correlation.
//
//   - EventType: A `EventType` is a string identifier for the kind of an audit event (e.g., "http_request_received", "auth_login").
//     The special `EventAny` constant allows subscribing to all events.
//
//   - Handler: A `Handler` is a function type `func(evt Event) error` that processes an incoming `Event`.
//     Handlers are subscribed to specific `EventType`s or to `EventAny`.
//
//   - BusConfig: The `BusConfig` struct holds all configurable parameters for the `Bus`,
//     allowing fine-grained control over its behavior, including buffer sizes, worker counts,
//     asynchronous behavior, sampling rates, spillover, memory limits, circuit breaker settings,
//     rate limiting, error handling, metrics, transport, and access control.
//     `DefaultBusConfig()` provides sensible defaults.
//
// Key Features:
//
// 1.  Event Publishing:
//     Events can be published to the bus using several methods:
//       - `Publish(evt Event)`: Publishes an event. If the bus is configured for asynchronous delivery (`Async: true`),
//         the event is placed into an internal queue for processing by workers. If the queue is full,
//         the event may be dropped or spilled to disk. If `Async` is `false`, it acts like `PublishSync`.
//       - `PublishSync(evt Event)`: Publishes an event synchronously, meaning all subscribed handlers for that event type
//         and global handlers are executed immediately within the calling goroutine.
//       - `PublishWithTimeout(evt Event, timeout time.Duration)`: Publishes an event asynchronously but blocks
//         until the event is accepted into the internal queue or the specified timeout is reached.
//         If the timeout is exceeded, an `ErrPublishTimeout` is returned, and the event may be spilled.
//
// 2.  Event Subscription:
//     Handlers can be registered to receive events using `Subscribe(et EventType, h Handler)`.
//     Multiple handlers can subscribe to the same event type. Handlers can also subscribe to `EventAny`
//     to receive all events.
//
// 3.  Event History:
//     The `Bus` maintains an in-memory history of recently published events, capped by `HistoryCap`.
//     - `History(ctx context.Context)`: Retrieves a slice of the stored historical events.
//     - `SetHistoryCap(n int)`: Dynamically adjusts the capacity of the history buffer.
//     The history also respects a `MaxMemoryMB` limit to prevent excessive memory consumption,
//     estimating event sizes to manage the memory footprint.
//
// 4.  Spillover to Disk:
//     When the internal event queue is full or the circuit breaker is open, events can be spilled to disk
//     if `SpilloverDir` is configured in `BusConfig`.
//     The `spilloverHandler` writes events as JSON lines to a log file.
//     The `RecoverSpillover()` method attempts to re-publish these spilled events when the bus
//     is operating normally and the queue has capacity.
//
// 5.  Rate Limiting:
//     The bus can enforce a publishing rate limit using the `RateLimit` and `RateBurst` parameters in `BusConfig`.
//     Events exceeding this rate are dropped or spilled.
//
// 6.  Circuit Breaker:
//     A `circuitBreaker` mechanism is integrated to protect the bus from continuously failing handlers
//     or external transports. If `CircuitMaxFails` consecutive handler errors occur within
//     a `CircuitTimeout`, the circuit opens, and events are dropped or spilled
//     instead of being processed, allowing the failing component to recover.
//
// 7.  Metrics Integration:
//     The `BusMetrics` interface defines a contract for reporting metrics such as
//     published events, dropped events, and handler latency.
//     `PrometheusMetrics` provides a Prometheus-compatible implementation,
//     and `nopMetrics` is a no-operation implementation for when metrics are not needed.
//     Metrics can be configured using `WithMetrics` or `WithMetricsRegisterer`.
//
// 8.  External Transport:
//     The `Transport` interface allows integrating external systems (e.g., message queues like Kafka)
//     for event persistence or further processing.
//     `KafkaTransport` is provided as a concrete implementation for sending events to Kafka,
//     supporting retries and asynchronous sending.
//     A transport can be set via `WithTransport`.
//
// Event Definition and Types:
//
// The package defines a comprehensive set of predefined `EventType` constants and
// corresponding `New...` helper functions for common application events.
// These include:
//   - HTTP Events: `EventTypeHTTPRequestReceived`, `EventTypeHTTPResponseSent`, `EventTypeHTTPRouteNotFound`, `EventTypeHTTPMethodNotAllowed`.
//   - Authentication Events: `EventTypeAuthRegister`, `EventTypeAuthLogin`, `EventTypeAuthLogout`, `EventTypeAuthTokenIssued`, `EventTypeAuthTokenRevoked`, `EventTypeAuthCredentialsChecked`.
//   - Database Events: `EventTypeDBConnected`, `EventTypeDBInit`, `EventTypeDBError`, `EventTypeDBQuery`, `EventTypeDBExec`, `EventTypeDBTxStarted`, `EventTypeDBTxCommitted`, `EventTypeDBTxRolledBack`.
//   - Work Item Events: `EventTypeWorkItemCreated`, `EventTypeWorkItemUpdated`, `EventTypeWorkItemDeleted`, `EventTypeWorkItemAssigned`, `EventTypeWorkItemUnassigned`, `EventTypeCustomFieldSet`.
//   - Comment & Attachment Events: `EventTypeCommentAdded`, `EventTypeCommentDeleted`, `EventTypeAttachmentAdded`, `EventTypeAttachmentRemoved`.
//   - User Events: `EventTypeUserCreated`, `EventTypeUserUpdated`, `EventTypeUserDeleted`, `EventTypeUserLoggedIn`, `EventTypeUserLoggedOut`.
//   - Team Events: `EventTypeTeamCreated`, `EventTypeTeamUpdated`, `EventTypeTeamDeleted`, `EventTypeTeamMemberAdded`, `EventTypeTeamMemberRemoved`.
//
// Generic Typed Events:
// The `EventT[T any]` interface and `BasicEventT[T any]` struct provide support for
// creating events with a specific, strongly-typed payload, enhancing compile-time safety and readability.
// For instance, `NewHTTPRequestReceivedT` creates an event with `HTTPRequestPayload`.
//
// Persistence and Observability:
//
// 1.  Logging Integration:
//     The `Logger` struct provides a high-level API for publishing various log-level events
//     (Info, Warning, Debug, Error, Fatal, AssertionFailed) to the `Bus`.
//     `SetupLogging` configures persistent storage for audit events:
//       - File-based logging using `lumberjack` for log rotation, compression, and retention.
//       - Database persistence to a SQL database (e.g., PostgreSQL, MySQL, SQLite) with batch insertion and retry logic.
//         `SetupDatabase` initializes the necessary `audit` table and indexes.
//     The `LogOption` functional options allow detailed configuration of file and database handlers.
//
// 2.  Schema Validation:
//     `EventSchema` allows defining expected fields and their types for an event's payload.
//     `RegisterSchema` is used to register these schemas, and `validatePayload`
//     ensures that published events conform to their registered schema, catching data inconsistencies early.
//     Predefined event types have their schemas registered during package initialization.
//
// Security and Data Integrity:
//
// 1.  Access Control for History:
//     The `AccessControlFunc` type defines a function that can be used to enforce
//     permissions before allowing access to the event history.
//     It can be configured using `WithAccessControl` in `BusConfig`.
//     `CheckHistoryAccess` provides a default role-based check (`"admin"`) if no custom function is provided.
//
// 2.  Payload Sanitization:
//     The `SanitizePayload` function automatically redacts sensitive information (e.g., "email", "password")
//     from event payloads before they are stored or processed further.
//     Custom `Sanitizer` functions can be defined and applied.
//
// 3.  Event Encryption:
//     `EncryptEvent` provides a mechanism to encrypt event payloads using AES-256 GCM,
//     ensuring that sensitive data is protected at rest or in transit.
//     `GenerateAESKey` can be used to generate strong encryption keys.
//
// Configuration:
//
// The `Bus` is initialized using `NewBus` with variadic `BusOption` functions.
// These options cover various aspects such as history capacity (`WithHistoryCap`),
// async buffer size (`WithBufferSize`), worker count (`WithWorkerCount`),
// asynchronous delivery (`WithAsync`), sampling rate (`WithSampleRate`),
// spillover directory (`WithSpilloverDir`), maximum memory usage (`WithMaxMemoryMB`),
// circuit breaker parameters (`WithCircuitBreaker`),
// metrics implementation (`WithMetrics`, `WithMetricsRegisterer`),
// external transport (`WithTransport`),
// access control for history (`WithAccessControl`), and rate limiting (`WithRateLimit`).
//
// Configuration can also be loaded from environment variables using `LoadConfigFromEnv()`.
//
// Usage Patterns:
//
// 1.  Initializing the Audit Bus:
//     bus, err := audit.NewBus(
//         audit.WithHistoryCap(1000),
//         audit.WithAsync(true),
//         audit.WithBufferSize(500),
//         audit.WithSpilloverDir("/var/log/audit"),
//         audit.WithMaxMemoryMB(50),
//         audit.WithMetricsRegisterer(prometheus.DefaultRegisterer),
//     )
//     if err != nil {
//         log.Fatalf("Failed to create audit bus: %v", err)
//     }
//     defer bus.Close()
//
// 2.  Subscribing a Handler:
//     bus.Subscribe(audit.EventTypeAuthLogin, func(evt audit.Event) error {
//         fmt.Printf("User %s logged in at %s\n", evt.Payload().(map[string]interface{})["user_id"], evt.Time())
//         return nil
//     })
//
// 3.  Publishing an Event:
//     ctx := context.Background()
//     // Assuming a user ID and source are available
//     loginEvent := audit.NewAuthLogin(ctx, "my-service", "user123")
//     bus.Publish(loginEvent)
//
// 4.  Setting up Persistent Logging:
//     db, err := sql.Open("sqlite3", "./audit.db") // Example using SQLite
//     if err != nil {
//         log.Fatalf("Failed to open database: %v", err)
//     }
//     if err := audit.SetupDatabase(db); err != nil {
//         log.Fatalf("Failed to setup audit database: %v", err)
//     }
//     closers, err := audit.SetupLogging(bus, db,
//         audit.WithFilePath("/var/log/app_audit.log"),
//         audit.WithDBBatchSize(50),
//     )
//     if err != nil {
//         log.Fatalf("Failed to setup logging: %v", err)
//     }
//     for _, closer := range closers {
//         defer closer()
//     }
//
// 5.  Using the Logger API:
//     logger := audit.NewLogger(bus)
//     logger.Info(ctx, "my-service", "Application started", map[string]string{"version": "1.0.0"})
//     logger.Error(ctx, "my-service", "Database connection failed", fmt.Errorf("connection refused"), nil)
//
// Concurrency:
//
// The `Bus` and its components are designed to be safe for concurrent use.
// Internal synchronization primitives (mutexes, atomic operations, channels, and wait groups)
// are used to protect shared data and manage concurrent access.
// Asynchronous event processing is handled by a worker pool.
//
// Error Handling:
//
// Errors during event processing by handlers or internal bus operations are typically
// reported via the `ErrorFunc` configured in `BusConfig`, which defaults to logging the error.
// For methods like `PublishWithTimeout`, specific errors are returned to the caller.
//
// This package aims to provide a comprehensive solution for managing audit events within Go applications,
// offering flexibility, performance, and resilience for critical operational insights.
package audit