package audit

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"github.com/cenkalti/backoff"
)

// Transport defines the interface for an external event delivery mechanism.
// Implementations of this interface are responsible for taking an audit Event
// and sending it to a destination such as a message queue, a database, or a remote API.
type Transport interface {
	// Start initializes the transport, performing any necessary setup like
	// connecting to external services. It should return an error if initialization fails.
	Start() error

	// Send attempts to deliver a single audit Event. Implementations should
	// handle any underlying network or service failures, possibly with retry logic.
	// It returns an error if the event cannot be sent after all attempts.
	Send(evt Event) error

	// Close shuts down the transport, releasing any held resources.
	// It should be called to ensure graceful termination and prevent resource leaks.
	Close() error
}

// KafkaTransport implements the Transport interface using Apache Kafka.
// It sends audit events as JSON messages to a specified Kafka topic.
type KafkaTransport struct {
	producer    sarama.SyncProducer // The Sarama producer used to send messages to Kafka.
	topic       string              // The Kafka topic to which events will be published.
	maxRetries  int                 // The maximum number of retries for sending a single event.
	retryDelay  time.Duration       // The initial delay between retry attempts for sending an event.
	async       bool                // Indicates if the Kafka producer operates in asynchronous mode.
}

// NewKafkaTransport creates and initializes a new KafkaTransport instance.
//
// It takes a slice of Kafka broker addresses, the target topic, and an optional
// set of functional options to configure the transport.
//
// The Kafka producer is configured for synchronous sending by default (waiting
// for broker acknowledgments), but can be switched to asynchronous mode via
// WithKafkaAsync.
//
// Parameters:
//   - brokers: A slice of strings, each representing a Kafka broker address (e.g., "localhost:9092").
//   - topic: The name of the Kafka topic where audit events will be published.
//   - opts:   Variadic functional options to customize the KafkaTransport's behavior.
//
// Returns:
//   - *KafkaTransport: A pointer to the newly created KafkaTransport instance.
//   - error: An error if the Kafka producer fails to initialize.
func NewKafkaTransport(brokers []string, topic string, opts ...KafkaOption) (*KafkaTransport, error) {
	config := sarama.NewConfig()
	// Default to synchronous production, waiting for broker acknowledgments
	config.Producer.Return.Successes = true

	t := &KafkaTransport{
		topic:      topic,
		maxRetries: 3,                  // Default max retries
		retryDelay: 500 * time.Millisecond, // Default initial retry delay
		async:      false,              // Default to synchronous sending
	}

	// Apply functional options to override defaults
	for _, opt := range opts {
		opt(t)
	}

	// If async option is enabled, configure Sarama producer accordingly
	if t.async {
		config.Producer.Return.Successes = false // For async, we don't wait for success responses
	}

	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}

	t.producer = producer
	return t, nil
}

// KafkaOption defines a functional option for configuring a KafkaTransport.
// These options allow for flexible and extensible configuration of the KafkaTransport.
type KafkaOption func(*KafkaTransport)

// WithKafkaRetries sets the maximum number of times the KafkaTransport will
// attempt to resend a failed event before giving up.
//
// A value of 0 means no retries after the initial attempt.
func WithKafkaRetries(n int) KafkaOption {
	return func(t *KafkaTransport) { t.maxRetries = n }
}

// WithKafkaRetryDelay sets the initial delay duration between retry attempts
// when sending an event to Kafka.
// The actual delay between attempts will increase exponentially based on this initial value.
func WithKafkaRetryDelay(d time.Duration) KafkaOption {
	return func(t *KafkaTransport) { t.retryDelay = d }
}

// WithKafkaAsync enables or disables asynchronous message production for the
// KafkaTransport.
//
// When async is true, `Send` calls will not wait for the Kafka broker's
// acknowledgment that the message was successfully received. This can improve
// throughput but means that success or failure is not immediately known to the caller.
// When async is false (default), `Send` will block until an acknowledgment is received.
func WithKafkaAsync(async bool) KafkaOption {
	return func(t *KafkaTransport) { t.async = async }
}

// Start initializes the KafkaTransport.
//
// For KafkaTransport, this method currently performs no specific startup
// operations beyond what is done during NewKafkaTransport.
// It always returns nil, indicating success.
func (t *KafkaTransport) Start() error {
	// Sarama producer is already initialized in NewKafkaTransport
	return nil
}

// Send marshals the given Event to JSON and sends it to the configured Kafka topic.
//
// It uses exponential backoff with a configurable number of retries and initial delay
// to handle transient errors during message transmission to Kafka.
//
// Parameters:
//   - evt: The audit Event to be sent.
//
// Returns:
//   - error: An error if marshaling fails or if the event cannot be sent to Kafka
//     after all retry attempts.
func (t *KafkaTransport) Send(evt Event) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: t.topic,
		Value: sarama.ByteEncoder(data), // Encode event data as bytes for Kafka
	}

	// Configure exponential backoff for retries
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = t.retryDelay
	// Set MaxElapsedTime to ensure retries don't go on forever.
	// A simple heuristic is maxRetries * InitialInterval * factor.
	b.MaxElapsedTime = time.Duration(t.maxRetries+1) * t.retryDelay * 2 // +1 for initial attempt

	// Execute SendMessage with retry logic
	return backoff.Retry(func() error {
		// SendMessage is blocking for SyncProducer. For AsyncProducer, it enqueues.
		_, _, err := t.producer.SendMessage(msg)
		return err // Return error to backoff to indicate failure
	}, b)
}

// Close shuts down the Kafka producer gracefully.
//
// It attempts to close the underlying Sarama producer, ensuring all buffered
// messages are sent and connections are properly terminated.
//
// Returns:
//   - error: An error if the producer fails to close cleanly.
func (t *KafkaTransport) Close() error {
	return t.producer.Close()
}