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

// RunFTP emulates just enough of the FTP control protocol (USER/PASS/QUIT)
// to capture credential attempts from scanners — it never implements data
// transfer, since nothing real is ever actually going to be served.
func RunFTP(cfg config.FTPConfig, pipe *Pipeline) error {
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.ListenAddr, err)
	}
	log.Printf("[ftp] listening on %s", cfg.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ftp] accept error: %v", err)
			continue
		}
		go handleFTPConn(conn, pipe)
	}
}

func handleFTPConn(conn net.Conn, pipe *Pipeline) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	host, portStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
	port, _ := strconv.Atoi(portStr)

	fmt.Fprint(conn, "220 ProFTPD 1.3.8 Server ready.\r\n")
	reader := bufio.NewReader(conn)

	var username string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}

		switch cmd {
		case "USER":
			username = arg
			fmt.Fprint(conn, "331 Password required.\r\n")
		case "PASS":
			fp := fingerprint.FromSignals(map[string]string{
				"username": username,
				"protocol": "ftp",
			})
			severity := store.SeverityMedium
			if username == "anonymous" {
				severity = store.SeverityLow
			}
			pipe.Record(&store.Event{
				Protocol:   "ftp",
				SourceIP:   host,
				SourcePort: port,
				Username:   username,
				Password:   arg,
				ClientHash: fp,
				Severity:   severity,
				SessionID:  fp + "-" + time.Now().Format("150405"),
			})
			time.Sleep(300 * time.Millisecond)
			fmt.Fprint(conn, "530 Login incorrect.\r\n")
		case "QUIT":
			fmt.Fprint(conn, "221 Goodbye.\r\n")
			return
		default:
			fmt.Fprint(conn, "502 Command not implemented.\r\n")
		}
	}
}
