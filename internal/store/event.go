package store

import "time"

// Event is one recorded interaction with a decoy service. Every protocol
// handler normalizes what it sees into this shape before it hits storage,
// so downstream consumers (dashboard, alerting, exports) don't need to
// know anything about SSH vs HTTP vs Telnet internals.
type Event struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Protocol    string    `json:"protocol"` // ssh, http, telnet, ftp
	SourceIP    string    `json:"source_ip"`
	SourcePort  int       `json:"source_port"`
	Country     string    `json:"country,omitempty"`
	City        string    `json:"city,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	ISP         string    `json:"isp,omitempty"`
	Username    string    `json:"username,omitempty"`
	Password    string    `json:"password,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Path        string    `json:"path,omitempty"`
	RawPayload  string    `json:"raw_payload,omitempty"`
	ClientHash  string    `json:"client_fingerprint,omitempty"`
	Severity    string    `json:"severity"`
	SessionID   string    `json:"session_id"`
	Notes       string    `json:"notes,omitempty"`
}

// Severity buckets drive both the dashboard color coding and the alert
// webhook's min_severity filter in config.yaml.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)
