package security

import (
	"log"
	"sync"
)

// Buffer accumulates matched events in memory between flushes. v1 has no
// local disk spillover (FR-1.5) — anything beyond maxBatch at flush time is
// dropped with a single logged warning, not queued anywhere durable.
type Buffer struct {
	mu       sync.Mutex
	events   []Event
	maxBatch int
}

// NewBuffer creates a Buffer capped at maxBatch events per flush. maxBatch
// <= 0 falls back to 200 (mirrors config.defaultSecurityEventsMaxBatch).
func NewBuffer(maxBatch int) *Buffer {
	if maxBatch <= 0 {
		maxBatch = 200
	}
	return &Buffer{maxBatch: maxBatch}
}

// Add appends events to the buffer (called from the tail poll loop).
func (b *Buffer) Add(events ...Event) {
	if len(events) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, events...)
}

// Len reports how many events are currently buffered (test/inspection helper).
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// Flush drains up to maxBatch events and passes them to send. Overflow
// beyond maxBatch is dropped unconditionally (logged once) regardless of
// whether send succeeds — v1 has no spillover, so excess events are gone the
// moment they exceed the cap. On send success, the sent batch is removed
// from the buffer. On send failure, the sent batch is NOT removed — it stays
// buffered for retry on the next flush (FR-2.5), and the error is returned
// to the caller.
func (b *Buffer) Flush(send func([]Event) error) error {
	b.mu.Lock()
	if len(b.events) == 0 {
		b.mu.Unlock()
		return nil
	}

	var batch []Event
	dropped := 0
	if len(b.events) <= b.maxBatch {
		batch = make([]Event, len(b.events))
		copy(batch, b.events)
	} else {
		batch = make([]Event, b.maxBatch)
		copy(batch, b.events[:b.maxBatch])
		dropped = len(b.events) - b.maxBatch
	}
	b.mu.Unlock()

	if dropped > 0 {
		log.Printf("security: flush dropped %d event(s) beyond max batch size (%d)", dropped, b.maxBatch)
	}

	err := send(batch)

	b.mu.Lock()
	defer b.mu.Unlock()
	toRemove := dropped
	if err == nil {
		toRemove += len(batch)
	}
	if toRemove > len(b.events) {
		toRemove = len(b.events)
	}
	b.events = b.events[toRemove:]

	return err
}
