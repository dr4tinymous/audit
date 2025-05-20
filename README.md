# Audit Package

[![Go Reference](https://pkg.go.dev/badge/github.com/dr4tinymous/audit.svg)](https://pkg.go.dev/github.com/dr4tinymous/audit)
[![Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org/)

The `audit` package is a robust, in-memory publish-subscribe bus designed for managing and processing audit events in Go applications. It provides high-throughput, low-latency event processing with features for resilience, observability, and data integrity. The package supports asynchronous event delivery, historical event storage, disk spillover, rate limiting, circuit breaking, metrics integration, and secure event handling.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Initializing the Audit Bus](#initializing-the-audit-bus)
  - [Subscribing to Events](#subscribing-to-events)
  - [Publishing Events](#publishing-events)
  - [Configuring Persistent Logging](#configuring-persistent-logging)
  - [Using the Logger API](#using-the-logger-api)
- [Event Types](#event-types)
- [Configuration Options](#configuration-options)
- [Security Features](#security-features)
- [Metrics and Observability](#metrics-and-observability)
- [External Transport](#external-transport)
- [Project Structure](#project-structure)
- [Mermaid Diagram](#mermaid-diagram)
- [License](#license)

## Overview
The `audit` package facilitates the management of audit events through a publish-subscribe model. The core component, `Bus`, enables applications to publish events, subscribe handlers to process them, and store event history. It is designed for concurrent use, ensuring thread-safety with internal synchronization mechanisms. The package includes features like disk spillover for backpressure, rate limiting, circuit breaking for fault tolerance, and integration with external systems like Kafka.

## Features
- **Event Publishing**: Supports synchronous (`PublishSync`), asynchronous (`Publish`), and timeout-based (`PublishWithTimeout`) event publishing.
- **Event Subscription**: Register handlers for specific event types or all events using `EventAny`.
- **Event History**: Maintains an in-memory history of events with configurable capacity and memory limits.
- **Spillover to Disk**: Writes events to disk when the queue is full or the circuit breaker is open, with recovery mechanisms.
- **Rate Limiting**: Enforces limits on event publishing to prevent overload.
- **Circuit Breaker**: Protects the system from failing handlers or transports by temporarily halting processing.
- **Metrics Integration**: Supports Prometheus metrics for monitoring published events, dropped events, and handler latency.
- **External Transport**: Integrates with external systems like Kafka for event persistence.
- **Security**: Includes payload sanitization, event encryption, and access control for history retrieval.
- **Logging**: Provides a high-level `Logger` API for info, warning, debug, error, fatal, and assertion events.
- **Schema Validation**: Ensures event payloads conform to predefined schemas.

## Architecture
The `audit` package is built around the `Bus` struct, which manages event publishing, subscription, and processing. Events are defined by the `Event` interface, with `BasicEvent` as the default implementation. Handlers process events, and the bus supports both synchronous and asynchronous modes. The architecture includes:

- **Event Queue**: Manages incoming events in asynchronous mode.
- **Worker Pool**: Processes events concurrently in async mode.
- **History Buffer**: Stores recent events with a configurable capacity.
- **Spillover Handler**: Persists events to disk during backpressure.
- **Circuit Breaker**: Monitors handler failures to prevent system overload.
- **Metrics**: Tracks performance and errors using a `BusMetrics` interface.
- **Transport**: Sends events to external systems like Kafka.

## Installation
To use the `audit` package, ensure you have Go installed. Then, import the package into your project:

```bash
go get github.com/dr4tinymous/audit
```

Ensure dependencies like `github.com/google/uuid`, `go.opentelemetry.io/otel/trace`, `golang.org/x/time/rate`, `github.com/IBM/sarama`, `github.com/natefinch/lumberjack`, and `github.com/prometheus/client_golang/prometheus` are installed.

## Usage
Below are examples of common usage patterns for the `audit` package.

### Initializing the Audit Bus
Create a new `Bus` with custom configuration options:

```go
package main

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/dr4tinymous/audit"
)

func main() {
	bus, err := audit.NewBus(
		audit.WithHistoryCap(1000),
		audit.WithAsync(true),
		audit.WithBufferSize(500),
		audit.WithSpilloverDir("/var/log/audit"),
		audit.WithMaxMemoryMB(50),
		audit.WithMetricsRegisterer(prometheus.DefaultRegisterer),
	)
	if err != nil {
		log.Fatalf("Failed to create audit bus: %v", err)
	}
	defer bus.Close()
}
```

### Subscribing to Events
Register a handler to process specific event types:

```go
bus.Subscribe(audit.EventTypeAuthLogin, func(evt audit.Event) error {
	log.Printf("User %s logged in at %s", evt.Payload().(map[string]interface{})["user_id"], evt.Time())
	return nil
})
```

### Publishing Events
Publish an event, such as a user login:

```go
import (
	"context"
	"github.com/dr4tinymous/audit"
)

func main() {
	ctx := context.Background()
	bus := audit.DefaultBus()
	defer bus.Close()

	loginEvent := audit.NewAuthLogin(ctx, "my-service", "user123")
	bus.Publish(loginEvent)
}
```

### Configuring Persistent Logging
Set up file and database logging:

```go
import (
	"database/sql"
	"log"
	"github.com/dr4tinymous/audit"
	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite3", "./audit.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	if err := audit.SetupDatabase(db); err != nil {
		log.Fatalf("Failed to setup audit database: %v", err)
	}

	bus := audit.DefaultBus()
	defer bus.Close()

	closers, err := audit.SetupLogging(bus, db,
		audit.WithFilePath("/var/log/app_audit.log"),
		audit.WithDBBatchSize(50),
	)
	if err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}
	for _, closer := range closers {
		defer closer()
	}
}
```

### Using the Logger API
Use the `Logger` for structured logging:

```go
logger := audit.NewLogger(bus)
ctx := context.Background()
logger.Info(ctx, "my-service", "Application started", map[string]string{"version": "1.0.0"})
logger.Error(ctx, "my-service", "Database connection failed", fmt.Errorf("connection refused"), nil)
```

## Event Types
The package defines several event types, each with associated schemas and helper functions:

- **HTTP Events**: `http_request_received`, `http_response_sent`, `http_route_not_found`, `http_method_not_allowed`
- **Authentication Events**: `auth_register`, `auth_login`, `auth_logout`, `auth_token_issued`, `auth_token_revoked`, `auth_credentials_checked`
- **Database Events**: `db_connected`, `db_init`, `db_error`, `db_query`, `db_exec`, `db_tx_started`, `db_tx_committed`, `db_tx_rolled_back`
- **Work Item Events**: `work_item_created`, `work_item_updated`, `work_item_deleted`, `work_item_assigned`, `work_item_unassigned`, `custom_field_set`
- **Comment & Attachment Events**: `comment_added`, `comment_deleted`, `attachment_added`, `attachment_removed`
- **User Events**: `user_created`, `user_updated`, `user_deleted`, `user_logged_in`, `user_logged_out`
- **Team Events**: `team_created`, `team_updated`, `team_deleted`, `team_member_added`, `team_member_removed`
- **Logging Events**: `log_info`, `log_warning`, `log_debug`, `log_error`, `log_fatal`, `log_assertion_failed`

## Configuration Options
The `Bus` can be configured using `BusOption` functions:

- `WithHistoryCap(n int)`: Sets the history buffer size.
- `WithBufferSize(n int)`: Sets the async queue size.
- `WithWorkerCount(n int)`: Sets the number of worker goroutines.
- `WithAsync(async bool)`: Enables/disables async delivery.
- `WithSampleRate(rate float64)`: Sets the sampling rate for events.
- `WithSpilloverDir(dir string)`: Sets the directory for disk spillover.
- `WithMaxMemoryMB(mb int)`: Sets the memory limit for history.
- `WithCircuitBreaker(timeout time.Duration, maxFails int)`: Configures circuit breaker parameters.
- `WithMetrics(metrics BusMetrics)`: Sets a custom metrics implementation.
- `WithMetricsRegisterer(registerer prometheus.Registerer)`: Configures Prometheus metrics.
- `WithTransport(transport Transport)`: Sets an external transport like Kafka.
- `WithAccessControl(f AccessControlFunc)`: Sets a custom access control function.
- `WithRateLimit(rate, burst int)`: Sets rate limiting parameters.

Environment variables can also be used to configure the bus via `LoadConfigFromEnv`.

## Security Features
- **Payload Sanitization**: Automatically redacts sensitive fields like `email` and `password` using `SanitizePayload`.
- **Event Encryption**: Supports AES-256 GCM encryption of event payloads with `EncryptEvent`.
- **Access Control**: Enforces permissions for history access via `AccessControlFunc` or a default admin role check.

## Metrics and Observability
The package integrates with Prometheus through `PrometheusMetrics`, tracking:
- Total published events (`audit_events_published_total`)
- Total dropped events (`audit_events_dropped_total`)
- Handler latency (`audit_handler_latency_seconds`)

Use `WithMetricsRegisterer` to enable Prometheus metrics.

## External Transport
The `Transport` interface allows integration with external systems. The `KafkaTransport` implementation sends events to Kafka with retry logic. Configure it with:

```go
kafka, err := audit.NewKafkaTransport([]string{"localhost:9092"}, "audit-topic")
if err != nil {
	log.Fatalf("Failed to create Kafka transport: %v", err)
}
bus, err := audit.NewBus(audit.WithTransport(kafka))
```

## Project Structure
The package is organized as follows:

```
audit/
├── bus.go              # Core Bus implementation
├── config.go           # Configuration options
├── doc.go              # Package documentation
├── event.go            # Event types and helpers
├── log.go              # Logging and persistence
├── metrics.go          # Metrics implementation
├── schema.go           # Event schema validation
├── security.go         # Security features
├── transport.go        # External transport integration
└── LICENSE.txt         # Unlicense
```

## Mermaid Diagram
Below is a Mermaid diagram illustrating the architecture of the `audit` package:

```mermaid
graph TD
    A[Client Application] -->|Publish| B[Bus]
    B -->|Queue| C[Event Queue]
    C -->|Dispatch| D[Worker Pool]
    D -->|Process| E[Handlers]
    B -->|Store| F[History Buffer]
    B -->|Spill| G[Spillover Handler]
    G -->|Write| H[Disk (spillover.log)]
    G -->|Recover| B
    B -->|Send| I[Transport (e.g., Kafka)]
    B -->|Record| J[Metrics]
    J -->|Export| K[Prometheus]
    B -->|Validate| L[Schema Registry]
    B -->|Sanitize/Encrypt| M[Security Module]
    F -->|Access| N[Access Control]
```

## License
This project is licensed under the Unlicense, which dedicates the software to the public domain. See [LICENSE.txt](LICENSE.txt) for details.