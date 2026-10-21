// Command sentryhive runs a multi-protocol honeypot: decoy SSH, HTTP,
// Telnet, and FTP services that log every connection attempt — source
// IP, approximate geolocation, credentials tried, and a rough client
// fingerprint — to a local SQLite database, with optional webhook
// alerting for anything above a configured severity.
//
// None of the decoy services ever grant real access. They exist purely
// to attract and record automated scanning/credential-stuffing traffic.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/KelvinNgeno/sentryhive/internal/alert"
	"github.com/KelvinNgeno/sentryhive/internal/config"
	"github.com/KelvinNgeno/sentryhive/internal/geoip"
	"github.com/KelvinNgeno/sentryhive/internal/services"
	"github.com/KelvinNgeno/sentryhive/internal/store"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatalf("creating data dir %s: %v", cfg.DataDir, err)
	}

	db, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}
	defer db.Close()

	var geo geoip.Lookup = geoip.NoopLookup{}
	if cfg.GeoIP.Provider == "ip-api" {
		geo = geoip.NewCached(geoip.NewIPAPI())
	}

	dispatcher := alert.NewDispatcher(cfg.Alerting.WebhookURL, cfg.Alerting.MinSeverity)

	pipe := &services.Pipeline{
		Store:  db,
		Geo:    geo,
		Alerts: dispatcher,
	}

	log.Printf("sentryhive starting — node=%s data_dir=%s", cfg.NodeName, filepath.Clean(cfg.DataDir))

	if cfg.Services.SSH.Enabled {
		go mustRun("ssh", func() error { return services.RunSSH(cfg.Services.SSH, pipe) })
	}
	if cfg.Services.HTTP.Enabled {
		go mustRun("http", func() error { return services.RunHTTP(cfg.Services.HTTP, pipe) })
	}
	if cfg.Services.Telnet.Enabled {
		go mustRun("telnet", func() error { return services.RunTelnet(cfg.Services.Telnet, pipe) })
	}
	if cfg.Services.FTP.Enabled {
		go mustRun("ftp", func() error { return services.RunFTP(cfg.Services.FTP, pipe) })
	}

	waitForShutdown()
	log.Println("sentryhive shutting down")
}

func mustRun(name string, fn func() error) {
	if err := fn(); err != nil {
		log.Fatalf("[%s] fatal: %v", name, err)
	}
}

func waitForShutdown() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
