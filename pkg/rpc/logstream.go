package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// LogRecord is the wire shape of a slog record forwarded to an
// adminLogs WebSocket subscriber.
type LogRecord struct {
	Time    string            `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

// LogStreamer is an slog.Handler that tees every record into a
// bounded in-memory ring (for history replay on subscribe) and fans
// them out to registered subscribers. The streamer is designed to
// replace the node's default slog handler: the original handler is
// invoked before the record is emitted to subscribers so console /
// file output stays identical.
type LogStreamer struct {
	inner        slog.Handler
	mu           sync.Mutex
	buffer       []LogRecord
	capacity     int
	subscribers  map[int64]chan<- LogRecord
	subID        int64
	defaultLevel slog.Level
}

// NewLogStreamer constructs a LogStreamer layered on top of `inner`.
// Records emitted through this handler are delivered to `inner` AND
// retained in the ring for adminLogs subscribers. When inner is nil,
// records are silently dropped (the streamer becomes an in-memory-
// only tee).
//
// capacity is the ring size — 2048 is plenty for operator debugging
// without unbounded memory growth; tune via the caller.
func NewLogStreamer(inner slog.Handler, capacity int) *LogStreamer {
	if capacity <= 0 {
		capacity = 2048
	}
	return &LogStreamer{
		inner:       inner,
		capacity:    capacity,
		buffer:      make([]LogRecord, 0, capacity),
		subscribers: make(map[int64]chan<- LogRecord),
	}
}

// Enabled matches the inner handler so filter behaviour stays
// consistent. When inner is nil the streamer enables everything.
func (s *LogStreamer) Enabled(ctx context.Context, level slog.Level) bool {
	if s.inner == nil {
		return level >= s.defaultLevel
	}
	return s.inner.Enabled(ctx, level)
}

// Handle records the slog.Record, forwards it to the inner handler,
// and delivers a serialised snapshot to every current subscriber.
func (s *LogStreamer) Handle(ctx context.Context, record slog.Record) error {
	if s.inner != nil {
		if err := s.inner.Handle(ctx, record); err != nil {
			// Don't swallow — the node's default logging path is the
			// primary source of truth.
			return err
		}
	}
	s.deliver(toLogRecord(record))
	return nil
}

// deliver pushes the LogRecord into the ring and fans it out to every
// current subscriber. Shared between LogStreamer.Handle and the
// derivedStreamer wrappers returned by WithAttrs / WithGroup so they
// see the same buffer + subscriber set as the root handler.
func (s *LogStreamer) deliver(rec LogRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.buffer) >= s.capacity {
		copy(s.buffer, s.buffer[1:])
		s.buffer = s.buffer[:len(s.buffer)-1]
	}
	s.buffer = append(s.buffer, rec)

	for _, ch := range s.subscribers {
		// Non-blocking send; a subscriber that can't keep up drops the
		// event (matches the eth_subscribe slow-consumer policy
		// elsewhere in this package).
		select {
		case ch <- rec:
		default:
		}
	}
}

// WithAttrs and WithGroup: delegate to inner when available, otherwise
// noop. The returned handler wraps the same streamer so every branch
// shares one subscriber set.
//
// Implementation: a derivedStreamer holds a pointer back to the
// originating LogStreamer for subscriber/buffer state and an
// independent inner slog.Handler with the requested attrs/group
// applied. Plain `ls := *s` would copy the LogStreamer's sync.Mutex,
// which is a vet copylocks violation and would also desync any
// concurrent Handle calls between the two handler instances.
func (s *LogStreamer) WithAttrs(attrs []slog.Attr) slog.Handler {
	if s.inner == nil {
		return s
	}
	return &derivedStreamer{streamer: s, inner: s.inner.WithAttrs(attrs)}
}

func (s *LogStreamer) WithGroup(name string) slog.Handler {
	if s.inner == nil {
		return s
	}
	return &derivedStreamer{streamer: s, inner: s.inner.WithGroup(name)}
}

// derivedStreamer is the WithAttrs/WithGroup wrapper. It shares the
// originating LogStreamer's subscriber + buffer state but applies its
// own (attrs- or group-augmented) inner slog.Handler.
type derivedStreamer struct {
	streamer *LogStreamer
	inner    slog.Handler
}

func (d *derivedStreamer) Enabled(ctx context.Context, level slog.Level) bool {
	return d.inner.Enabled(ctx, level)
}

func (d *derivedStreamer) Handle(ctx context.Context, record slog.Record) error {
	if err := d.inner.Handle(ctx, record); err != nil {
		return err
	}
	rec := toLogRecord(record)
	d.streamer.deliver(rec)
	return nil
}

func (d *derivedStreamer) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &derivedStreamer{streamer: d.streamer, inner: d.inner.WithAttrs(attrs)}
}

func (d *derivedStreamer) WithGroup(name string) slog.Handler {
	return &derivedStreamer{streamer: d.streamer, inner: d.inner.WithGroup(name)}
}

// Subscribe registers a channel to receive new log records. It also
// replays the current ring so subscribers see recent history
// immediately on connect.
//
// The returned cancel function must be called when the subscriber
// goes away; failing to do so leaks the channel reference inside the
// streamer.
func (s *LogStreamer) Subscribe(buffer int) (<-chan LogRecord, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan LogRecord, buffer)

	s.mu.Lock()
	s.subID++
	id := s.subID
	s.subscribers[id] = ch
	// Drain the ring to the new subscriber non-blockingly — if they
	// can't keep up with history, drop the tail; new events are what
	// matters.
	for _, rec := range s.buffer {
		select {
		case ch <- rec:
		default:
		}
	}
	s.mu.Unlock()

	cancel := func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
		// Do NOT close(ch) here — the consumer goroutine reads from
		// the channel; closing while it's blocked on <-ch is the
		// cancel semantics we want. Close after a small delay to
		// flush any in-flight sends.
		go func() {
			time.Sleep(50 * time.Millisecond)
			defer func() { recover() }()
			close(ch)
		}()
	}
	return ch, cancel
}

// toLogRecord renders an slog.Record into the wire-format LogRecord
// that subscribers consume.
func toLogRecord(rec slog.Record) LogRecord {
	attrs := map[string]string{}
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = attrValueString(a.Value)
		return true
	})
	level := strings.ToUpper(rec.Level.String())
	return LogRecord{
		Time:    rec.Time.UTC().Format(time.RFC3339Nano),
		Level:   level,
		Message: rec.Message,
		Attrs:   attrs,
	}
}

// attrValueString collapses a structured slog value into a string.
// Maps and slices are JSON-encoded so they survive the string round
// trip without going through reflection noise.
func attrValueString(v slog.Value) string {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return intBase10(v.Int64())
	case slog.KindUint64:
		return uintBase10(v.Uint64())
	case slog.KindBool:
		if v.Bool() {
			return "true"
		}
		return "false"
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindAny:
		raw, err := json.Marshal(v.Any())
		if err != nil {
			buf := bytes.Buffer{}
			buf.WriteString("<unserialisable>")
			return buf.String()
		}
		return string(raw)
	default:
		return v.String()
	}
}

func intBase10(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func uintBase10(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
