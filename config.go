package main

import (
	_ "embed"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed default.yml
var defaultConfigYAML []byte

// ---------------- STRUCTS ----------------

type Config struct {
	Server    ServerConfig `yaml:"server"`
	Proxies   []Proxy      `yaml:"proxies"`
	Timeouts  Timeouts     `yaml:"timeouts"`
	DPI       DPIConfig    `yaml:"dpi"`
	UserAgent string       `yaml:"userAgent"`
	Cache     Cache        `yaml:"cache"`
}

type ServerConfig struct {
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	CertPath      string `yaml:"certPath"`
	CacheFile     string `yaml:"cacheFile"`
	UserCacheFile string `yaml:"userCacheFile"`
}

type Proxy struct {
	URL           string           `yaml:"url"`
	ParsedURL     *url.URL         `yaml:"-"`
	Blacklist     []string         `yaml:"blacklist"`
	blackcompiled []*regexp.Regexp `yaml:"-"`
	Whitelist     []string         `yaml:"whitelist"`
	whitecompiled []*regexp.Regexp `yaml:"-"`
}

type Timeouts struct {
	CheckProxy       CheckProxyTimeouts `yaml:"checkProxy"`
	ClientConnection ClientTimeouts     `yaml:"clientConnection"`
}

type CheckProxyTimeouts struct {
	TLSHandshakeTimeout   int `yaml:"TLSHandshakeTimeout"`   // ms
	ResponseHeaderTimeout int `yaml:"responseHeaderTimeout"` // ms
	ExpectContinueTimeout int `yaml:"expectContinueTimeout"` // ms
	DialContext           int `yaml:"dialContext"`           // ms
	Timeout               int `yaml:"timeout"`               // ms
}

type ClientTimeouts struct {
	Timeout   int `yaml:"timeout"`   // ms
	KeepAlive int `yaml:"keepAlive"` // ms
}

type DPIConfig struct {
	UploadProbe          UploadProbe `yaml:"uploadProbe"`
	RetryAttempts        int         `yaml:"retryAttempts"`
	UsePUTinRechecks     bool        `yaml:"usePUTinRechecks"`
	RecheckLimit         int         `yaml:"recheckLimit"`
	RecheckWindowSeconds int         `yaml:"recheckWindowSeconds"`
}

type UploadProbe struct {
	TotalSizeBytes int `yaml:"totalSizeBytes"`
	ChunkSizeBytes int `yaml:"chunkSizeBytes"`
	DelayMS        int `yaml:"delayMS"`
}

type Cache struct {
	TTL             time.Duration `yaml:"ttl"`
	MaxAge          time.Duration `yaml:"maxAge"`
	SaveTime        time.Duration `yaml:"saveTime"`
	CleanupInterval time.Duration `yaml:"cleanupInterval"`
}

// ---------------- LOAD ----------------

func LoadConfig(path string) (*Config, error) {

	// 1. дефолт из embed
	if err := yaml.Unmarshal(defaultConfigYAML, &cfg); err != nil {
		return nil, fmt.Errorf("parse default config: %w", err)
	}

	// 2. пользовательский конфиг (опционально)
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}

		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	// 3. валидация
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// ---------------- VALIDATION ----------------

func validateConfig(c *Config) error {
	if c.Server.Port == 0 {
		return fmt.Errorf("server.port is required")
	}

	if len(c.Proxies) == 0 {
		return fmt.Errorf("no proxies defined")
	}

	for i := range c.Proxies {
		p := &c.Proxies[i]

		if p.URL == "" {
			return fmt.Errorf("proxy[%d].url is required", i)
		}

		u, err := url.Parse(p.URL)
		if err != nil {
			return fmt.Errorf("proxy[%d] invalid url %q: %w", i, p.URL, err)
		}
		p.ParsedURL = u

		for _, pattern := range p.Blacklist {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("proxy[%d] invalid blacklist regex %q: %w", i, pattern, err)
			}
			p.blackcompiled = append(p.blackcompiled, re)
		}

		for _, pattern := range p.Whitelist {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("proxy[%d] invalid whitelist regex %q: %w", i, pattern, err)
			}
			p.whitecompiled = append(p.whitecompiled, re)
		}
	}

	if c.DPI.RetryAttempts < 0 {
		return fmt.Errorf("dpi.retryAttempts must be >= 0")
	}
	if c.DPI.RecheckLimit <= 0 {
		return fmt.Errorf("cache.recheckLimit must be > 0")
	}
	if c.DPI.RecheckWindowSeconds <= 0 {
		return fmt.Errorf("cache.recheckWindowSeconds must be > 0")
	}

	return nil
}
