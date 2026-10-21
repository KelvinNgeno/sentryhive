package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/KelvinNgeno/sentryhive/internal/store"
)

var severityRank = map[string]int{
	store.SeverityLow:      0,
	store.SeverityMedium:   1,
	store.SeverityHigh:     2,
	store.SeverityCritical: 3,
}

type Dispatcher struct {
	webhookURL  string
	minSeverity string
	client      *http.Client
}

func NewDispatcher(webhookURL, minSeverity string) *Dispatcher {
	if minSeverity == "" {
		minSeverity = store.SeverityMedium
	}
	return &Dispatcher{
		webhookURL:  webhookURL,
		minSeverity: minSeverity,
		client:      &http.Client{Timeout: 5 * time.Second},
	}
}

func (d *Dispatcher) Notify(e *store.Event) error {
	if d.webhookURL == "" {
		return nil // alerting disabled, not an error
	}
	if severityRank[e.Severity] < severityRank[d.minSeverity] {
		return nil
	}

	body := map[string]any{
		"text": fmt.Sprintf(
			"[%s] %s hit on %s from %s (%s, %s) — user=%q pass=%q",
			e.Severity, e.Protocol, e.Timestamp.Format(time.RFC3339),
			e.SourceIP, e.City, e.Country, e.Username, e.Password,
		),
		"event": e,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling alert payload: %w", err)
	}

	resp, err := d.client.Post(d.webhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
