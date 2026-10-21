package services

import (
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/KelvinNgeno/sentryhive/internal/config"
	"github.com/KelvinNgeno/sentryhive/internal/fingerprint"
	"github.com/KelvinNgeno/sentryhive/internal/store"
)

// RunHTTP serves a believable fake device/admin login page. The goal is
// plausibility, not completeness — most scanners never render JS or
// follow more than one or two links, so the persona just needs to survive
// a GET, a POST with credentials, and a couple of common path probes.
func RunHTTP(cfg config.HTTPConfig, pipe *Pipeline) error {
	mux := http.NewServeMux()
	persona := loadPersona(cfg.Persona)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		recordHTTPHit(pipe, r, "", "")
		w.Header().Set("Server", persona.ServerHeader)
		w.Write([]byte(persona.LoginPage))
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			user := r.FormValue("username")
			pass := r.FormValue("password")
			recordHTTPHit(pipe, r, user, pass)
			w.Header().Set("Server", persona.ServerHeader)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(persona.LoginFailedPage))
			return
		}
		w.Header().Set("Server", persona.ServerHeader)
		w.Write([]byte(persona.LoginPage))
	})

	// Common paths automated scanners probe for regardless of what the
	// landing page says — answering them (instead of 404ing) keeps bots
	// engaged longer and produces more fingerprinting signal.
	for _, path := range []string{"/.env", "/wp-login.php", "/manager/html", "/api/v1/users", "/cgi-bin/luci"} {
		p := path
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			recordHTTPHit(pipe, r, "", "")
			w.Header().Set("Server", persona.ServerHeader)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
		})
	}

	log.Printf("[http] listening on %s (persona: %s)", cfg.ListenAddr, cfg.Persona)
	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func recordHTTPHit(pipe *Pipeline, r *http.Request, user, pass string) {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	port, _ := strconv.Atoi(portStr)

	ua := r.UserAgent()
	fp := fingerprint.FromSignals(map[string]string{
		"user_agent": ua,
		"accept":     r.Header.Get("Accept"),
		"protocol":   "http",
	})

	severity := store.SeverityLow
	if user != "" || pass != "" {
		severity = store.SeverityMedium
	}
	if r.URL.Path == "/.env" || r.URL.Path == "/wp-login.php" {
		severity = store.SeverityMedium
	}

	pipe.Record(&store.Event{
		Protocol:   "http",
		SourceIP:   host,
		SourcePort: port,
		Username:   user,
		Password:   pass,
		UserAgent:  ua,
		Path:       r.URL.Path,
		ClientHash: fp,
		Severity:   severity,
		SessionID:  fp + "-" + time.Now().Format("150405"),
	})
}

type persona struct {
	ServerHeader    string
	LoginPage       string
	LoginFailedPage string
}

// loadPersona returns a canned page set. Kept intentionally simple and
// static (no templating engine) — real device admin pages are usually
// crusty, inconsistent HTML, and that's exactly what sells the decoy.
func loadPersona(name string) persona {
	return persona{
		ServerHeader: "lighttpd/1.4.59",
		LoginPage: `<!DOCTYPE html>
<html><head><title>Router Login</title></head>
<body style="font-family:Tahoma,Arial;background:#e8e8e8;">
<div style="width:320px;margin:80px auto;background:#fff;padding:20px;border:1px solid #ccc;">
<h2 style="color:#333;">Wireless Router Administration</h2>
<form method="POST" action="/login">
Username: <input type="text" name="username"><br><br>
Password: <input type="password" name="password"><br><br>
<input type="submit" value="Login">
</form>
</div></body></html>`,
		LoginFailedPage: `<!DOCTYPE html>
<html><body><p style="color:red;font-family:Tahoma">Invalid username or password.</p>
<a href="/login">Try again</a></body></html>`,
	}
}
