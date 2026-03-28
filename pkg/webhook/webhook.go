package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	EventScanCompleted     = "scan.completed"
	EventScanFailed        = "scan.failed"
	EventCriticalVulnFound = "vulnerability.critical_found"
)

type Payload struct {
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	Image     string    `json:"image,omitempty"`
	OrgID     string    `json:"org_id,omitempty"`
	ImageID   string    `json:"image_id,omitempty"`
	Status    string    `json:"status,omitempty"`
	Summary   Summary   `json:"summary,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type Summary struct {
	Total    int            `json:"total"`
	Critical int            `json:"critical"`
	High     int            `json:"high"`
	Medium   int            `json:"medium"`
	Low      int            `json:"low"`
	Scanners []string       `json:"scanners,omitempty"`
}

type Registration struct {
	ID     string   `json:"id"`
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret,omitempty"`
}

type Notifier struct {
	mu            sync.RWMutex
	registrations []Registration
	client        *http.Client
	maxRetries    int
}

func NewNotifier() *Notifier {
	n := &Notifier{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		maxRetries: 3,
	}

	if url := os.Getenv("OTTER_WEBHOOK_URL"); url != "" {
		n.registrations = append(n.registrations, Registration{
			ID:     "default",
			URL:    url,
			Events: []string{EventScanCompleted, EventScanFailed, EventCriticalVulnFound},
		})
	}

	return n
}

func (n *Notifier) Register(reg Registration) {
	n.mu.Lock()
	defer n.mu.Unlock()

	for i, existing := range n.registrations {
		if existing.ID == reg.ID {
			n.registrations[i] = reg
			return
		}
	}
	n.registrations = append(n.registrations, reg)
}

func (n *Notifier) Unregister(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	for i, reg := range n.registrations {
		if reg.ID == id {
			n.registrations = append(n.registrations[:i], n.registrations[i+1:]...)
			return
		}
	}
}

func (n *Notifier) List() []Registration {
	n.mu.RLock()
	defer n.mu.RUnlock()

	result := make([]Registration, len(n.registrations))
	copy(result, n.registrations)
	return result
}

func (n *Notifier) Notify(ctx context.Context, payload Payload) {
	n.mu.RLock()
	targets := make([]Registration, 0)
	for _, reg := range n.registrations {
		if matchesEvent(reg.Events, payload.Event) {
			targets = append(targets, reg)
		}
	}
	n.mu.RUnlock()

	for _, target := range targets {
		go n.deliver(ctx, target, payload)
	}
}

func matchesEvent(events []string, event string) bool {
	for _, e := range events {
		if e == event || e == "*" {
			return true
		}
	}
	return false
}

func (n *Notifier) deliver(ctx context.Context, reg Registration, payload Payload) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("webhook: marshal payload for %s: %v", reg.URL, err)
		return
	}

	var isSlack bool
	if strings.Contains(reg.URL, "hooks.slack.com") {
		isSlack = true
		body = formatSlackPayload(payload)
	}

	backoff := time.Second
	for attempt := 0; attempt <= n.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, reg.URL, bytes.NewReader(body))
		if err != nil {
			log.Printf("webhook: create request for %s: %v", reg.URL, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Otter-Webhook/1.0")
		if !isSlack {
			req.Header.Set("X-Otter-Event", payload.Event)
		}

		resp, err := n.client.Do(req)
		if err != nil {
			log.Printf("webhook: deliver to %s (attempt %d): %v", reg.URL, attempt+1, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		log.Printf("webhook: deliver to %s (attempt %d): status %d", reg.URL, attempt+1, resp.StatusCode)
	}
	log.Printf("webhook: exhausted retries for %s event=%s", reg.URL, payload.Event)
}

func formatSlackPayload(p Payload) []byte {
	var emoji, color string
	switch p.Event {
	case EventScanCompleted:
		emoji = ":white_check_mark:"
		color = "#36a64f"
	case EventScanFailed:
		emoji = ":x:"
		color = "#dc3545"
	case EventCriticalVulnFound:
		emoji = ":rotating_light:"
		color = "#dc3545"
	}

	text := fmt.Sprintf("%s *%s* | `%s`", emoji, p.Event, p.Image)
	if p.Summary.Total > 0 {
		text += fmt.Sprintf("\nVulnerabilities: *%d* total | Critical: %d | High: %d | Medium: %d | Low: %d",
			p.Summary.Total, p.Summary.Critical, p.Summary.High, p.Summary.Medium, p.Summary.Low)
	}
	if p.Error != "" {
		text += fmt.Sprintf("\nError: %s", p.Error)
	}

	slack := map[string]any{
		"attachments": []map[string]any{
			{
				"color": color,
				"text":  text,
			},
		},
	}

	data, _ := json.Marshal(slack)
	return data
}
