package security

import (
	"errors"
	"testing"
	"time"
)

func makeEvents(n int) []Event {
	events := make([]Event, n)
	for i := range events {
		events[i] = Event{Type: EventSSHAuthFail, Ts: time.Now(), Username: "u", SourceIP: "1.2.3.4"}
	}
	return events
}

func TestBuffer_FlushSendsAllWhenUnderCap(t *testing.T) {
	b := NewBuffer(200)
	b.Add(makeEvents(5)...)

	var sent []Event
	err := b.Flush(func(batch []Event) error {
		sent = batch
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sent) != 5 {
		t.Fatalf("expected 5 events sent, got %d", len(sent))
	}
	if b.Len() != 0 {
		t.Fatalf("expected buffer empty after successful flush, got %d", b.Len())
	}
}

func TestBuffer_FlushCapsAtMaxBatchAndDropsOverflow(t *testing.T) {
	b := NewBuffer(10)
	b.Add(makeEvents(15)...)

	var sent []Event
	err := b.Flush(func(batch []Event) error {
		sent = batch
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sent) != 10 {
		t.Fatalf("expected exactly maxBatch (10) events sent, got %d", len(sent))
	}
	// Overflow (5) is dropped unconditionally, sent batch removed on success.
	if b.Len() != 0 {
		t.Fatalf("expected buffer empty (sent + dropped overflow both removed), got %d", b.Len())
	}
}

func TestBuffer_FailedFlushKeepsBatchBufferedForRetry(t *testing.T) {
	b := NewBuffer(200)
	b.Add(makeEvents(5)...)

	err := b.Flush(func(batch []Event) error {
		return errors.New("network error")
	})
	if err == nil {
		t.Fatal("expected an error from Flush")
	}
	if b.Len() != 5 {
		t.Fatalf("expected all 5 events still buffered after failed flush, got %d", b.Len())
	}
}

func TestBuffer_FailedFlushStillDropsOverflow(t *testing.T) {
	b := NewBuffer(10)
	b.Add(makeEvents(15)...)

	err := b.Flush(func(batch []Event) error {
		return errors.New("network error")
	})
	if err == nil {
		t.Fatal("expected an error from Flush")
	}
	// The sent 10 stay buffered for retry, but the 5 overflow beyond the cap
	// are dropped unconditionally per FR-1.5 (no spillover), even on failure.
	if b.Len() != 10 {
		t.Fatalf("expected 10 events retained (overflow dropped regardless of send outcome), got %d", b.Len())
	}
}

func TestBuffer_FlushOnEmptyBufferIsNoop(t *testing.T) {
	b := NewBuffer(200)
	called := false
	err := b.Flush(func(batch []Event) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatal("send should not be called when the buffer is empty")
	}
}
