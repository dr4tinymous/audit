package audit

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"github.com/cenkalti/backoff"
)

// Transport defines an interface for external event transport.
type Transport interface {
	Start() error
	Send(evt Event) error
	Close() error
}

// KafkaTransport implements Transport using Kafka.
type KafkaTransport struct {
	producer    sarama.SyncProducer
	topic       string
	maxRetries  int
	retryDelay  time.Duration
	async       bool
}

// NewKafkaTransport creates a Kafka transport.
func NewKafkaTransport(brokers []string, topic string, opts ...KafkaOption) (*KafkaTransport, error) {
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	t := &KafkaTransport{
		topic:      topic,
		maxRetries: 3,
		retryDelay: 500 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(t)
	}
	if t.async {
		config.Producer.Return.Successes = false
	}
	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}
	t.producer = producer
	return t, nil
}

// KafkaOption configures KafkaTransport.
type KafkaOption func(*KafkaTransport)

// WithKafkaRetries sets the number of retries.
func WithKafkaRetries(n int) KafkaOption {
	return func(t *KafkaTransport) { t.maxRetries = n }
}

// WithKafkaRetryDelay sets the initial retry delay.
func WithKafkaRetryDelay(d time.Duration) KafkaOption {
	return func(t *KafkaTransport) { t.retryDelay = d }
}

// WithKafkaAsync enables asynchronous producing.
func WithKafkaAsync(async bool) KafkaOption {
	return func(t *KafkaTransport) { t.async = async }
}

// Start initializes the transport.
func (t *KafkaTransport) Start() error {
	return nil
}

// Send sends an event to Kafka with retry logic.
func (t *KafkaTransport) Send(evt Event) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	msg := &sarama.ProducerMessage{
		Topic: t.topic,
		Value: sarama.ByteEncoder(data),
	}
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = t.retryDelay
	b.MaxElapsedTime = time.Duration(t.maxRetries) * t.retryDelay * 2
	return backoff.Retry(func() error {
		_, _, err := t.producer.SendMessage(msg)
		return err
	}, b)
}

// Close shuts down the transport.
func (t *KafkaTransport) Close() error {
	return t.producer.Close()
}