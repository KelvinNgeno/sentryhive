package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	NodeName string         `yaml:"node_name"`
	DataDir  string         `yaml:"data_dir"`
	Services ServicesConfig `yaml:"services"`
	GeoIP    GeoIPConfig    `yaml:"geoip"`
	Alerting AlertConfig    `yaml:"alerting"`
}

type ServicesConfig struct {
	SSH    SSHConfig    `yaml:"ssh"`
	HTTP   HTTPConfig   `yaml:"http"`
	Telnet TelnetConfig `yaml:"telnet"`
	FTP    FTPConfig    `yaml:"ftp"`
}

type SSHConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Banner     string `yaml:"banner"`
	HostKeyPEM string `yaml:"host_key_path"`
}

type HTTPConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Persona    string `yaml:"persona"` // which fake site profile to serve
}

type TelnetConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
}

type FTPConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
}

type GeoIPConfig struct {
	Provider string `yaml:"provider"` // "mmdb" or "ip-api"
	MMDBPath string `yaml:"mmdb_path"`
}

type AlertConfig struct {
	WebhookURL      string `yaml:"webhook_url"`
	MinSeverity     string `yaml:"min_severity"`
	DedupeWindowSec int    `yaml:"dedupe_window_sec"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := defaultConfig()
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}

func defaultConfig() *Config {
	return &Config{
		NodeName: "sentryhive-01",
		DataDir:  "./data",
		Services: ServicesConfig{
			SSH:    SSHConfig{Enabled: true, ListenAddr: "0.0.0.0:2222", Banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3"},
			HTTP:   HTTPConfig{Enabled: true, ListenAddr: "0.0.0.0:8080", Persona: "router-admin"},
			Telnet: TelnetConfig{Enabled: true, ListenAddr: "0.0.0.0:2323"},
			FTP:    FTPConfig{Enabled: true, ListenAddr: "0.0.0.0:2121"},
		},
		GeoIP: GeoIPConfig{Provider: "ip-api"},
		Alerting: AlertConfig{
			MinSeverity:     "medium",
			DedupeWindowSec: 300,
		},
	}
}
