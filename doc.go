// Package audit provides a production-grade, thread-safe event bus for auditing,
// monitoring, and correlating events in distributed Go applications. It supports
// high-throughput, low-latency environments with synchronous and asynchronous
// publishing, configurable worker pools, rate limiting, circuit breaking,
// in-memory history, disk spillover, schema validation, payload sanitization,
// AES-256 GCM encryption, and integrations with Prometheus (metrics) and
// OpenTelemetry (tracing). It also supports pluggable transports (Kafka, HTTP,
// database) for flexible delivery.
//
// Key Features:
//   - Event Publishing: synchronous and asynchronous modes with configurable worker pools.
//   - Event History: in-memory buffering with configurable capacity and access control.
//   - Reliability: rate limiting, circuit breaking, disk spillover for persistence.
//   - Observability: integrates with Prometheus (metrics) and OpenTelemetry (tracing).
//   - Custom Transports: Kafka, HTTP, database, or custom sinks via Transport interface.
//   - Typed Events: predefined event types with schema validation.
//   - Security: payload sanitization, AES-256 GCM encryption, access control.
//   - Structured Logging: configurable persistence to files or databases.
//
// Version Compatibility:
//   • Go 1.21+ (tested; slight warnings on 1.20).
//   • Requires Go generics (1.18+).
//   • KafkaTransport (optional) uses Sarama v1.35+.
//
// Design Decisions:
//   - Functional Options: simplifies configuration and extensibility.
//   - Channel-Based Worker Pool: backpressure and bounded concurrency.
//   - Pluggable Error Handling: ErrorFunc for custom strategies.
//   - Circuit Breaker: protects external transports from cascading failures.
//   - Disk Spillover: persist events during overload/outages via SpillHandler.
//   - In-Memory History: replay and debugging with access control.
//   - Sanitization & Encryption: data privacy via Sanitizer and AES-GCM.
//   - No Global State: all config flows through NewBus or DefaultBusConfig.
//
// Architecture Overview:
//
//       Publisher ──► Bus
//                      │
//              ┌───────┴───────┐
//              │               │
//          RateLimiter    CircuitBreaker
//              │               │
//             pass           open/closed
//              │               │
//      Async Queue ──► Worker Pool ──► Handler(s)
//              │
//         SpillHandler
//              │
//          Transport
//
// Error Handling:
//   - Publish, PublishWithTimeout, and Sync publish invoke ErrorFunc on errors.
//   - RateLimiter drops and spills excess events.
//   - CircuitBreaker opens after max failures, resets after timeout.
//   - SpillHandler writes atomically and supports recovery.
//
// Usage Example:
//
//     bus, err := audit.NewBus(
//         audit.WithAsync(true),
//         audit.WithWorkerCount(5),
//         audit.WithRateLimit(100, 200),
//         audit.WithSpilloverDir("/var/log/audit/spill"),
//     )
//     if err != nil {
//         log.Fatalf("Failed to create audit bus: %v", err)
//     }
//     defer bus.Close()
//
//     bus.Subscribe(audit.EventTypeAuthLogin, func(evt audit.Event) error {
//         fmt.Printf("Received %s at %s: %+v\n", evt.Type(), evt.Time(), evt.Payload())
//         return nil
//     })
//
//     ctx := audit.WithContextID(context.Background(), "req-12345")
//     evt := audit.NewAuthLogin(ctx, "auth-service", "user42")
//     bus.Publish(evt)
//
// Configuration:
//   Use functional options (WithAsync, WithBufferSize, WithRateLimit, WithSpilloverDir,
//   WithCircuitBreaker, WithMetrics, WithTransport, etc.), or LoadConfigFromEnv.
//
// Event Types:
//   Predefined: HTTP (http_request_received, http_response_sent), Authentication
//   (auth_login, auth_register), Database (db_query, db_exec), WorkItem, Comment,
//   Attachment, User, Team, Logging, etc. Register custom types and schemas.
//
// Security Features:
//   - Sanitization: redact sensitive fields.
//   - Encryption: AES-256 GCM via EncryptEvent & GenerateAESKey.
//   - Access Control: history retrieval via CheckHistoryAccess.
//
// Logging:
//   Use Logger API (NewLogger, SetupLogging) for structured logging,
//   file rotation, batch DB inserts, and retry strategies.
//
// License:
//   Unlicense. See LICENSE.txt for details.
package audit
