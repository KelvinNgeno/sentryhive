# sentryhive

A multi-protocol honeypot written in Go. It runs decoy SSH, HTTP, Telnet,
and FTP services, logs every connection attempt (source IP, rough geo
location, credentials tried, a basic client fingerprint), and can push
alerts to a webhook when something interesting shows up. Everything lands
in a local SQLite file so you can query it directly or build a dashboard
on top later.

None of the services ever grant access — SSH and Telnet always reject
auth, the HTTP login form always returns invalid credentials, FTP never
accepts a login. The point is to attract and record scanning/brute-force
traffic, not to provide any real functionality to whoever connects.

## Why

Most of the traffic hitting an exposed server's SSH/HTTP/Telnet/FTP ports
within minutes of going live is automated: credential stuffing bots,
Mirai-derived IoT scanners, generic vuln probes. Running a few decoy
services alongside (or instead of) your real ones gives you a feed of
what's actively being tried against you — which IP ranges, which
credential lists, which paths get probed first.

## Services

| Protocol | Default port | What it emulates |
|----------|---------------|-------------------|
| SSH      | 2222          | OpenSSH 9.6, accepts any username, logs password/keyboard-interactive attempts |
| HTTP     | 8080          | Generic router/IoT admin login page, plus a handful of commonly-scanned paths (`/.env`, `/wp-login.php`, etc.) |
| Telnet   | 2323          | Bare DVR/embedded-device login prompt — this is what most Mirai-style scanners expect |
| FTP      | 2121          | Minimal control-channel implementation (USER/PASS/QUIT only, no data transfer) |

Ports default to unprivileged values above 1024 so you don't need root to
run it directly. For a production deployment that needs to listen on 22,
80, 23, 21 themselves, either put it behind `iptables`/`nftables` port
forwarding rules (recommended — keeps the binary unprivileged) or grant
`CAP_NET_BIND_SERVICE` as shown in `deploy/sentryhive.service`.

## Quick start

```bash
git clone https://github.com/KelvinNgeno/sentryhive.git
cd sentryhive
go mod tidy
make run
```

This starts all four services using `config.yaml` and writes events to
`./data/events.db`.

Query recent hits:

```bash
sqlite3 data/events.db "select timestamp, protocol, source_ip, country, username, password from events order by timestamp desc limit 20;"
```

## Configuration

Everything lives in `config.yaml`:

```yaml
services:
  ssh:
    enabled: true
    listen_addr: "0.0.0.0:2222"
    banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3"
  http:
    enabled: true
    listen_addr: "0.0.0.0:8080"
    persona: router-admin

geoip:
  provider: ip-api   # free, no key, rate-limited — swap to mmdb for volume

alerting:
  webhook_url: ""    # Slack/Discord-style incoming webhook
  min_severity: medium
```

Disable any service you don't want by setting `enabled: false`. Each one
runs as an independent goroutine, so turning one off doesn't affect the
others.

### GeoIP

Defaults to [ip-api.com](https://ip-api.com)'s free endpoint — no API key,
but rate-limited to roughly 45 requests/minute, and results are cached
in-memory per IP so repeat hits from the same scanner don't cost extra
lookups. For higher volume, download a GeoLite2 database from MaxMind
(free account required) and set `geoip.provider: mmdb` with the path to
the `.mmdb` file. The database itself isn't bundled here — MaxMind's
license doesn't allow redistributing it.

### Alerting

If `alerting.webhook_url` is set, events at or above `min_severity` get
POSTed as JSON (Slack/Discord incoming-webhook compatible format). Severity
is assigned per protocol — e.g. an SSH attempt from a known scanning tool's
client string, or a Telnet login with `root`/`admin` (the classic
Mirai default), is bumped to `high`.

## Fingerprinting

There's no TLS handshake on these plaintext decoys, so this isn't a
JA3/JA4 implementation. Instead, each handler hashes together whatever
signals it can observe — SSH client version string, HTTP header values,
Telnet username pattern — into a short id (`internal/fingerprint`). It's
enough to notice "this is the same script hitting three of my decoys"
without pretending to be more rigorous than it is.

## Running in Docker

```bash
docker build -t sentryhive .
docker run -d --name sentryhive \
  -p 2222:2222 -p 8080:8080 -p 2323:2323 -p 2121:2121 \
  -v $(pwd)/data:/app/data \
  sentryhive
```

## Running as a systemd service

See `deploy/sentryhive.service`. Copy the built binary and `config.yaml`
to `/opt/sentryhive`, create a `sentryhive` system user, then:

```bash
sudo cp deploy/sentryhive.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentryhive
```

## Project layout

```
cmd/sentryhive/       entrypoint, wires config + storage + services together
internal/config/      YAML config loading
internal/store/       SQLite-backed event storage
internal/geoip/       IP → location/ASN resolution (ip-api or local mmdb)
internal/fingerprint/ lightweight client fingerprinting
internal/alert/       webhook dispatch with severity filtering
internal/services/    the four protocol handlers (ssh, http, telnet, ftp)
deploy/               systemd unit
```

## Known limitations

- SQLite only — fine for a single node, not built for multi-node
  aggregation. If you're running several instances, point the webhook at
  something that can centralize events (ELK, a simple ingest API, etc.).
- The HTTP persona set is small (one router-admin login page plus a
  handful of commonly-probed paths). Extending `internal/services/http.go`
  with more personas is straightforward — it's just static HTML plus a
  route.
- No TLS/HTTPS decoy yet. On the list.
- Severity scoring is heuristic, not exhaustive — treat it as a rough
  triage signal, not ground truth.

## License

MIT — see `LICENSE`.
