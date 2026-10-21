// Package fingerprint builds a short stable hash out of whatever signals
// a given protocol handler can observe about a connecting client (SSH
// client version string, HTTP header order/values, Telnet negotiation
// options). It's not a full JA3/JA4 implementation — there's no TLS
// handshake to inspect on these plaintext decoys — but it's enough to
// tell "same script hitting multiple honeypots" apart from "unrelated
// scanners that happen to share an IP range" when you're triaging logs.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// FromSignals hashes a set of key/value signals into a short, stable id.
// Order of insertion doesn't matter — signals are sorted by key first —
// so callers can build the map in whatever order is convenient.
func FromSignals(signals map[string]string) string {
	keys := make([]string, 0, len(signals))
	for k := range signals {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(signals[k])
		sb.WriteByte('|')
	}

	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])[:16]
}
