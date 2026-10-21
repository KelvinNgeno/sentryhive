// Package geoip resolves an attacker's source IP to a rough location and
// network owner. Two backends are supported:
//
//   - "ip-api": free, no API key, ~45 requests/minute per the provider's
//     published limits. Fine for a low-traffic honeypot, not for anything
//     high volume — swap to the mmdb backend if you're getting rate limited.
//   - "mmdb": a local MaxMind GeoLite2 database file you download yourself
//     (requires a free MaxMind account; the license doesn't let us bundle
//     the database in this repo).
package geoip

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type Result struct {
	Country string
	City    string
	ASN     string
	ISP     string
}

type Lookup interface {
	Resolve(ip string) (Result, error)
}

// cachingClient wraps any Lookup with an in-memory cache so repeated hits
// from the same scanner IP (very common — bots retry constantly) don't
// each cost an outbound API call.
type cachingClient struct {
	inner Lookup
	mu    sync.RWMutex
	cache map[string]Result
}

func NewCached(inner Lookup) Lookup {
	return &cachingClient{inner: inner, cache: make(map[string]Result)}
}

func (c *cachingClient) Resolve(ip string) (Result, error) {
	c.mu.RLock()
	if r, ok := c.cache[ip]; ok {
		c.mu.RUnlock()
		return r, nil
	}
	c.mu.RUnlock()

	r, err := c.inner.Resolve(ip)
	if err != nil {
		return r, err
	}

	c.mu.Lock()
	c.cache[ip] = r
	c.mu.Unlock()
	return r, nil
}

type ipAPIClient struct {
	httpClient *http.Client
}

func NewIPAPI() Lookup {
	return &ipAPIClient{httpClient: &http.Client{Timeout: 5 * time.Second}}
}

type ipAPIResponse struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	AS          string `json:"as"`
	Message     string `json:"message"`
}

func (c *ipAPIClient) Resolve(ip string) (Result, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Result{}, fmt.Errorf("invalid ip: %s", ip)
	}
	if parsed.IsPrivate() || parsed.IsLoopback() {
		return Result{Country: "local", City: "local"}, nil
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,city,isp,as", ip)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return Result{}, fmt.Errorf("geoip request: %w", err)
	}
	defer resp.Body.Close()

	var parsed2 ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed2); err != nil {
		return Result{}, fmt.Errorf("decoding geoip response: %w", err)
	}
	if parsed2.Status != "success" {
		return Result{}, fmt.Errorf("geoip lookup failed: %s", parsed2.Message)
	}

	return Result{
		Country: parsed2.Country,
		City:    parsed2.City,
		ISP:     parsed2.ISP,
		ASN:     parsed2.AS,
	}, nil
}

// NoopLookup is used when geoip is disabled or misconfigured — keeps the
// rest of the pipeline from having to nil-check everywhere.
type NoopLookup struct{}

func (NoopLookup) Resolve(ip string) (Result, error) {
	return Result{}, nil
}
