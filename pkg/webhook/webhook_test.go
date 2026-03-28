package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNotifierDeliversToMatchingWebhooks(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.Header.Get("X-Otter-Event") != EventScanCompleted {
			t.Errorf("expected event header %q, got %q", EventScanCompleted, r.Header.Get("X-Otter-Event"))
		}
		var payload Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		if payload.Image != "alpine:3.18" {
			t.Errorf("expected image alpine:3.18, got %s", payload.Image)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := &Notifier{
		client:     server.Client(),
		maxRetries: 0,
	}
	n.Register(Registration{
		ID:     "test",
		URL:    server.URL,
		Events: []string{EventScanCompleted},
	})

	n.Notify(context.Background(), Payload{
		Event:     EventScanCompleted,
		Timestamp: time.Now(),
		Image:     "alpine:3.18",
	})

	// Wait briefly for async delivery
	time.Sleep(100 * time.Millisecond)
	if received.Load() != 1 {
		t.Fatalf("expected 1 delivery, got %d", received.Load())
	}
}

func TestNotifierSkipsNonMatchingEvents(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := &Notifier{
		client:     server.Client(),
		maxRetries: 0,
	}
	n.Register(Registration{
		ID:     "test",
		URL:    server.URL,
		Events: []string{EventScanFailed},
	})

	n.Notify(context.Background(), Payload{
		Event: EventScanCompleted,
	})

	time.Sleep(100 * time.Millisecond)
	if received.Load() != 0 {
		t.Fatalf("expected 0 deliveries for non-matching event, got %d", received.Load())
	}
}

func TestNotifierRetriesOnFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attempts.Add(1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := &Notifier{
		client:     server.Client(),
		maxRetries: 3,
	}
	n.Register(Registration{
		ID:     "retry-test",
		URL:    server.URL,
		Events: []string{"*"},
	})

	n.Notify(context.Background(), Payload{Event: EventScanCompleted})
	time.Sleep(8 * time.Second)

	if attempts.Load() < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", attempts.Load())
	}
}

func TestNotifierRegisterAndUnregister(t *testing.T) {
	n := NewNotifier()

	n.Register(Registration{ID: "a", URL: "http://a.com", Events: []string{"*"}})
	n.Register(Registration{ID: "b", URL: "http://b.com", Events: []string{"*"}})

	if len(n.List()) < 2 {
		t.Fatal("expected at least 2 registrations")
	}

	n.Unregister("a")
	for _, reg := range n.List() {
		if reg.ID == "a" {
			t.Fatal("expected registration 'a' to be removed")
		}
	}
}
