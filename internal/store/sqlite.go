package store

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func Open(dataDir string) (*SQLiteStore, error) {
	path := filepath.Join(dataDir, "events.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		protocol TEXT NOT NULL,
		source_ip TEXT NOT NULL,
		source_port INTEGER,
		country TEXT,
		city TEXT,
		asn TEXT,
		isp TEXT,
		username TEXT,
		password TEXT,
		user_agent TEXT,
		path TEXT,
		raw_payload TEXT,
		client_fingerprint TEXT,
		severity TEXT,
		session_id TEXT,
		notes TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("applying schema: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Save(e *Event) error {
	_, err := s.db.Exec(`
		INSERT INTO events
		(timestamp, protocol, source_ip, source_port, country, city, asn, isp,
		 username, password, user_agent, path, raw_payload, client_fingerprint,
		 severity, session_id, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Protocol, e.SourceIP, e.SourcePort, e.Country, e.City,
		e.ASN, e.ISP, e.Username, e.Password, e.UserAgent, e.Path, e.RawPayload,
		e.ClientHash, e.Severity, e.SessionID, e.Notes,
	)
	return err
}

// RecentFromIP supports the dedupe logic in the alert dispatcher so a
// single noisy scanner doesn't trigger a webhook per packet.
func (s *SQLiteStore) CountFromIPSince(ip string, sinceSeconds int) (int, error) {
	row := s.db.QueryRow(
		`SELECT COUNT(*) FROM events WHERE source_ip = ? AND timestamp >= datetime('now', ?)`,
		ip, fmt.Sprintf("-%d seconds", sinceSeconds),
	)
	var count int
	err := row.Scan(&count)
	return count, err
}

func (s *SQLiteStore) TopAttackers(limit int) (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT source_ip, COUNT(*) as c FROM events GROUP BY source_ip ORDER BY c DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int)
	for rows.Next() {
		var ip string
		var count int
		if err := rows.Scan(&ip, &count); err != nil {
			return nil, err
		}
		result[ip] = count
	}
	return result, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
