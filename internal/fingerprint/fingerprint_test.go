package fingerprint

import "testing"

func TestFromSignals_StableRegardlessOfInsertionOrder(t *testing.T) {
	a := FromSignals(map[string]string{"client_version": "SSH-2.0-libssh", "protocol": "ssh"})
	b := FromSignals(map[string]string{"protocol": "ssh", "client_version": "SSH-2.0-libssh"})

	if a != b {
		t.Fatalf("expected same hash regardless of map iteration order, got %q vs %q", a, b)
	}
}

func TestFromSignals_DifferentInputsDifferentHashes(t *testing.T) {
	a := FromSignals(map[string]string{"protocol": "ssh", "client_version": "SSH-2.0-libssh"})
	b := FromSignals(map[string]string{"protocol": "ssh", "client_version": "SSH-2.0-OpenSSH_9.6"})

	if a == b {
		t.Fatalf("expected different hashes for different client versions, both got %q", a)
	}
}

func TestFromSignals_Length(t *testing.T) {
	h := FromSignals(map[string]string{"a": "b"})
	if len(h) != 16 {
		t.Fatalf("expected 16-character fingerprint, got %d chars: %q", len(h), h)
	}
}
