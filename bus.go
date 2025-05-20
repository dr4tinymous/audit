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
type EventType string

// EventAny is used to subscribe to all events.
const EventAny EventType = "*"

// Event represents an occurrence to be audited.
type Event interface {
	ID() string
	Type() EventType
	Time() time.Time
	Source() string
	ContextID() string
	Payload() interface{}
	SpanContext() trace.SpanContext
}

// BasicEvent is a simple implementation of Event.
type BasicEvent struct {
	IDVal        string
	TypeVal      EventType
	TimeVal      time.Time
	SourceVal    string
	ContextIDVal string
	PayloadVal   interface{}
	SpanCtx      trace.SpanContext
}

var _ Event = (*BasicEvent)(nil)

func (e BasicEvent) ID() string                    { return e.IDVal }
func (e BasicEvent) Type() EventType               { return e.TypeVal }
func (e BasicEvent) Time() time.Time               { return e.TimeVal }
func (e BasicEvent) Source() string                { return e.SourceVal }
func (e BasicEvent) ContextID() string             { return e.ContextIDVal }
func (e BasicEvent) Payload() interface{}          { return e.PayloadVal }
func (e BasicEvent) SpanContext() trace.SpanContext { return e.SpanCtx }

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

// Handler processes an incoming Event.
type Handler func(evt Event) error

// handlerTask represents a task for the worker pool.
type handlerTask struct {
	h   Handler
	evt Event
}

// BusConfig holds parameters to configure a Bus.
type BusConfig struct {
	HistoryCap      int
	BufferSize      int
	WorkerCount     int
	Async           bool
	SampleRate      float64
	SpilloverDir    string
	MaxMemoryMB     int
	CircuitTimeout  time.Duration
	CircuitMaxFails int
	RateLimit       int
	RateBurst       int
	ErrorFunc       func(error, Event)
	Metrics         BusMetrics
	Transport       Transport
	AccessControl   AccessControlFunc
}

func DefaultBusConfig() BusConfig {
	return BusConfig{
		HistoryCap:      10000,
		BufferSize:      1000,
		WorkerCount:     8,
		Async:           true,
		SampleRate:      1.0,
		SpilloverDir:    "",
		MaxMemoryMB:     100,
		CircuitTimeout:  30 * time.Second,
		CircuitMaxFails: 5,
		RateLimit:       1000,
		RateBurst:       1000,
		ErrorFunc:       func(err error, evt Event) { log.Printf("audit.Bus error: %v for event ID %s", err, evt.ID()) },
		Metrics:         nopMetrics{},
		Transport:       nil,
		AccessControl:   nil,
	}
}

// Bus is an in-memory publish/subscribe bus for audit events.
type Bus struct {
	mu            sync.RWMutex
	handlers      map[EventType][]Handler
	global        []Handler
	history       []Event
	historyCap    int
	queueSize     int
	async         bool
	sampleRate    float64
	spillover     *spilloverHandler
	errorFunc     func(error, Event)
	metrics       BusMetrics
	transport     Transport
	accessControl AccessControlFunc
	eventQueue    chan Event
	taskQueue     chan handlerTask
	workerWg      sync.WaitGroup
	circuit       *circuitBreaker
	memoryLimit   int64
	memoryUsed    int64
	closed        atomic.Bool
	limiter       *rate.Limiter
}

func NewBus(opts ...BusOption) (*Bus, error) {
	cfg := DefaultBusConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = nopMetrics{}
	}
	b := &Bus{
		handlers:      make(map[EventType][]Handler),
		history:       make([]Event, 0, cfg.HistoryCap),
		historyCap:    cfg.HistoryCap,
		queueSize:     cfg.BufferSize,
		async:         cfg.Async,
		sampleRate:    cfg.SampleRate,
		errorFunc:     cfg.ErrorFunc,
		metrics:       cfg.Metrics,
		transport:     cfg.Transport,
		accessControl: cfg.AccessControl,
		memoryLimit:   int64(cfg.MaxMemoryMB) * 1024 * 1024,
		circuit:       newCircuitBreaker(cfg.CircuitTimeout, cfg.CircuitMaxFails),
		limiter:       rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateBurst),
	}
	if cfg.SpilloverDir != "" {
		var err error
		b.spillover, err = newSpilloverHandler(cfg.SpilloverDir)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize spillover: %w", err)
		}
	}
	if b.async {
		b.eventQueue = make(chan Event, b.queueSize)
		b.taskQueue = make(chan handlerTask, cfg.BufferSize)
		for i := 0; i < cfg.WorkerCount; i++ {
			b.workerWg.Add(1)
			go b.worker()
		}
		b.workerWg.Add(1)
		go b.dispatchLoop()
		if b.spillover != nil {
			b.workerWg.Add(1)
			go b.recoverSpilloverLoop()
		}
	}
	if b.transport != nil {
		if err := b.transport.Start(); err != nil {
			return nil, fmt.Errorf("failed to start transport: %w", err)
		}
		b.Subscribe(EventAny, b.transport.Send)
	}
	return b, nil
}

func (b *Bus) recoverSpilloverLoop() {
	defer b.workerWg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if b.circuit.IsClosed() && len(b.eventQueue) < b.queueSize/2 {
				if err := b.RecoverSpillover(); err != nil {
					b.errorFunc(fmt.Errorf("spillover recovery failed: %w", err), nil)
				}
			}
		case <-b.eventQueue:
			return
		}
	}
}

func (b *Bus) RecoverSpillover() error {
	if b.spillover == nil {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(b.spillover.dir, "spillover.log"), os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open spillover file: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var events []Event
	for scanner.Scan() {
		var evt BasicEvent
		if err := json.Unmarshal(scanner.Bytes(), &evt); err != nil {
			continue
		}
		events = append(events, &evt)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read spillover file: %w", err)
	}
	for _, evt := range events {
		if b.canStoreEvent(evt) {
			b.Publish(evt)
		}
	}
	return f.Truncate(0)
}

func DefaultBus() *Bus {
	bus, err := NewBus()
	if err != nil {
		log.Fatalf("Failed to create default bus: %v", err)
	}
	return bus
}

func (b *Bus) Close() {
	if !b.closed.CompareAndSwap(false, true) {
		return
	}
	if b.async {
		close(b.eventQueue)
		b.workerWg.Wait()
	}
	if b.spillover != nil {
		_ = b.spillover.Close()
	}
	if b.transport != nil {
		_ = b.transport.Close()
	}
}

func (b *Bus) Subscribe(et EventType, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if et == EventAny {
		b.global = append(b.global, h)
	} else {
		b.handlers[et] = append(b.handlers[et], h)
	}
}

var ErrPublishTimeout = fmt.Errorf("audit bus: publish timeout")

func (b *Bus) Publish(evt Event) {
	if b.closed.Load() {
		b.errorFunc(fmt.Errorf("bus closed"), evt)
		return
	}
	if b.limiter != nil {
		if !b.limiter.Allow() {
			b.spillEvent(evt)
			b.metrics.EventDropped(evt.Type())
			b.errorFunc(fmt.Errorf("rate limit exceeded"), evt)
			return
		}
	}
	evt = b.prepareEvent(evt)
	if evt == nil {
		return
	}
	if b.async {
		b.publishAsync(evt)
	} else {
		b.publishSync(evt)
	}
}

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

func (b *Bus) PublishWithTimeout(evt Event, timeout time.Duration) error {
	if b.closed.Load() {
		return fmt.Errorf("bus closed")
	}
	evt = b.prepareEvent(evt)
	if evt == nil {
		return nil
	}
	if !b.async {
		b.publishSync(evt)
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case b.eventQueue <- evt:
		b.metrics.EventPublished(evt.Type())
		return nil
	case <-timer.C:
		b.metrics.EventDropped(evt.Type())
		b.spillEvent(evt)
		b.errorFunc(ErrPublishTimeout, evt)
		return ErrPublishTimeout
	}
}

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

func (b *Bus) SetSampleRate(rate float64) {
	if rate < 0 || rate > 1 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sampleRate = rate
}

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
		b.spillEvent(evt)
		b.metrics.EventDropped(evt.Type())
		b.errorFunc(fmt.Errorf("event dropped, queue full"), evt)
	}
}

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

	for _, h := range append(local, global...) {
		start := time.Now()
		if err := h(evt); err != nil {
			b.circuit.RecordFailure()
			b.errorFunc(err, evt)
		} else {
			b.circuit.RecordSuccess()
		}
		b.metrics.HandlerLatency(evt.Type(), time.Since(start))
	}
}

func (b *Bus) recordHistory(evt Event) {
	if b.historyCap <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.history) >= b.historyCap {
		excess := b.history[0]
		b.memoryUsed -= estimateEventSize(excess)
		b.history = b.history[1:]
	}
	b.history = append(b.history, evt)
	b.memoryUsed += estimateEventSize(evt)
}

func (b *Bus) canStoreEvent(evt Event) bool {
	size := estimateEventSize(evt)
	return atomic.AddInt64(&b.memoryUsed, size) <= b.memoryLimit
}

func (b *Bus) spillEvent(evt Event) {
	if b.spillover != nil {
		_ = b.spillover.Write(evt)
	}
}

func (b *Bus) shouldSample() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sampleRate == 1.0 || rand.Float64() < b.sampleRate
}

func (b *Bus) dispatchLoop() {
	defer b.workerWg.Done()
	for evt := range b.eventQueue {
		b.mu.RLock()
		local := append([]Handler(nil), b.handlers[evt.Type()]...)
		global := append([]Handler(nil), b.global...)
		b.mu.RUnlock()

		for _, h := range append(local, global...) {
			b.taskQueue <- handlerTask{h, evt}
		}
	}
	close(b.taskQueue)
}

func (b *Bus) worker() {
	defer b.workerWg.Done()
	for task := range b.taskQueue {
		start := time.Now()
		if err := task.h(task.evt); err != nil {
			b.circuit.RecordFailure()
			b.errorFunc(err, task.evt)
		} else {
			b.circuit.RecordSuccess()
		}
		b.metrics.HandlerLatency(task.evt.Type(), time.Since(start))
	}
}

type spilloverHandler struct {
	dir  string
	file *os.File
	mu   sync.Mutex
}

func newSpilloverHandler(dir string) (*spilloverHandler, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "spillover.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &spilloverHandler{dir: dir, file: f}, nil
}

func (h *spilloverHandler) Write(evt Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	_, err = h.file.Write(append(data, '\n'))
	return err
}

func (h *spilloverHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.file.Close()
}

type circuitBreaker struct {
	mu         sync.Mutex
	state      int32
	fails      int
	maxFails   int
	timeout    time.Duration
	lastFail   time.Time
}

func newCircuitBreaker(timeout time.Duration, maxFails int) *circuitBreaker {
	return &circuitBreaker{
		state:    0,
		maxFails: maxFails,
		timeout:  timeout,
	}
}

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

func (cb *circuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.fails++
	cb.lastFail = time.Now()
	if cb.fails >= cb.maxFails {
		atomic.StoreInt32(&cb.state, 1)
	}
}

func (cb *circuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if atomic.LoadInt32(&cb.state) == 0 {
		cb.fails = 0
	}
}

func ensureID(evt Event) Event {
	if evt.ID() == "" {
		return &idEvent{Event: evt, id: uuid.New().String()}
	}
	return evt
}

type idEvent struct {
	Event
	id string
}

func (e *idEvent) ID() string { return e.id }

func ensureTime(evt Event) Event {
	if evt.Time().IsZero() {
		return &timeEvent{Event: evt, t: time.Now()}
	}
	return evt
}

type timeEvent struct {
	Event
	t time.Time
}

func (e *timeEvent) Time() time.Time { return e.t }

func ensureSpanContext(evt Event) Event {
	if !evt.SpanContext().IsValid() {
		return &spanEvent{Event: evt, spanCtx: trace.SpanContextFromContext(context.Background())}
	}
	return evt
}

type spanEvent struct {
	Event
	spanCtx trace.SpanContext
}

func (e *spanEvent) SpanContext() trace.SpanContext { return e.spanCtx }

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