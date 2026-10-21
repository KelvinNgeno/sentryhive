package services

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/KelvinNgeno/sentryhive/internal/config"
	"github.com/KelvinNgeno/sentryhive/internal/fingerprint"
	"github.com/KelvinNgeno/sentryhive/internal/store"
)

// RunTelnet emulates the login prompt of a cheap IoT/embedded device —
// this is the single most scanned-for decoy type on the internet thanks
// to Mirai-style botnets, so it's worth getting the prompt text right.
func RunTelnet(cfg config.TelnetConfig, pipe *Pipeline) error {
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.ListenAddr, err)
	}
	log.Printf("[telnet] listening on %s", cfg.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[telnet] accept error: %v", err)
			continue
		}
		go handleTelnetConn(conn, pipe)
	}
}

func handleTelnetConn(conn net.Conn, pipe *Pipeline) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)
	host, portStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
	port, _ := strconv.Atoi(portStr)

	fmt.Fprint(conn, "\r\nDVR-Login: ")
	user, err := readLine(reader)
	if err != nil {
		return
	}

	fmt.Fprint(conn, "Password: ")
	pass, err := readLine(reader)
	if err != nil {
		return
	}

	fp := fingerprint.FromSignals(map[string]string{
		"username": user,
		"protocol": "telnet",
	})

	severity := store.SeverityMedium
	if user == "root" || user == "admin" {
		severity = store.SeverityHigh // classic Mirai-style default creds
	}

	pipe.Record(&store.Event{
		Protocol:   "telnet",
		SourceIP:   host,
		SourcePort: port,
		Username:   user,
		Password:   pass,
		ClientHash: fp,
		Severity:   severity,
		SessionID:  fp + "-" + time.Now().Format("150405"),
	})

	// Stall briefly like a device actually checking credentials, then
	// deny — never grant a shell, obviously.
	time.Sleep(600 * time.Millisecond)
	fmt.Fprint(conn, "\r\nLogin incorrect\r\n")
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
