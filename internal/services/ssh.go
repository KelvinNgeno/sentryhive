package services

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/KelvinNgeno/sentryhive/internal/config"
	"github.com/KelvinNgeno/sentryhive/internal/fingerprint"
	"github.com/KelvinNgeno/sentryhive/internal/store"
)

// RunSSH starts a decoy SSH server. It never grants access — every
// credential pair is recorded and rejected, with a small delay so brute
// forcers don't instantly realize the host never accepts anything, and
// so slow drip of attempts gives the fingerprinting signals time to build
// up (client version string, auth method sequence).
func RunSSH(cfg config.SSHConfig, pipe *Pipeline) error {
	signer, err := ephemeralHostKey()
	if err != nil {
		return fmt.Errorf("generating host key: %w", err)
	}

	sshConfig := &ssh.ServerConfig{
		ServerVersion: cfg.Banner,
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			handleSSHAttempt(pipe, meta, string(password))
			time.Sleep(400 * time.Millisecond) // looks like a real slow auth check
			return nil, fmt.Errorf("authentication failed")
		},
		KeyboardInteractiveCallback: func(meta ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			handleSSHAttempt(pipe, meta, "")
			return nil, fmt.Errorf("authentication failed")
		},
	}
	sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.ListenAddr, err)
	}
	log.Printf("[ssh] listening on %s (banner: %s)", cfg.ListenAddr, cfg.Banner)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ssh] accept error: %v", err)
			continue
		}
		go func() {
			defer conn.Close()
			// This handshake always ends in an error since no auth
			// method ever succeeds — that's expected, not a bug.
			_, _, _, _ = ssh.NewServerConn(conn, sshConfig)
		}()
	}
}

func handleSSHAttempt(pipe *Pipeline, meta ssh.ConnMetadata, password string) {
	host, portStr, _ := net.SplitHostPort(meta.RemoteAddr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	clientVersion := string(meta.ClientVersion())
	fp := fingerprint.FromSignals(map[string]string{
		"client_version": clientVersion,
		"protocol":       "ssh",
	})

	severity := store.SeverityMedium
	if isKnownOffensiveTool(clientVersion) {
		severity = store.SeverityHigh
	}

	pipe.Record(&store.Event{
		Protocol:   "ssh",
		SourceIP:   host,
		SourcePort: port,
		Username:   meta.User(),
		Password:   password,
		ClientHash: fp,
		Severity:   severity,
		SessionID:  fp + "-" + time.Now().Format("150405"),
		RawPayload: clientVersion,
	})
}

func isKnownOffensiveTool(clientVersion string) bool {
	v := strings.ToLower(clientVersion)
	markers := []string{"libssh", "paramiko", "pysftp", "ncrack", "medusa", "hydra"}
	for _, m := range markers {
		if strings.Contains(v, m) {
			return true
		}
	}
	return false
}

func ephemeralHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}
