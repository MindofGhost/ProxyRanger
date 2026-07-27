package main

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CacheEntry struct {
	Value     string
	CreatedAt time.Time
}

var (
	cache      = make(map[string]CacheEntry) // main domain -> upstream proxy
	userCache  = make(map[string]string)
	cacheMu    sync.RWMutex
	inProgress sync.Map // key: domain, value: chan struct{}
	recheckMu  sync.Mutex
	rechecks   = make(map[string][]time.Time) // main domain -> recent recheck starts
	certPool   *x509.CertPool
	cfg        Config
)

func loadCerts(dir string) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("CA directory %s does not exist - skipping", dir)
			return pool
		}
		log.Printf("Failed to read %s: %v", dir, err)
		return pool
	}

	added := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		ext := filepath.Ext(file.Name())
		if ext != ".crt" && ext != ".pem" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			log.Printf("Failed to read %s: %v", file.Name(), err)
			continue
		}

		if pool.AppendCertsFromPEM(data) {
			added++
		} else {
			log.Printf("Failed to append certificate %s", file.Name())
		}
	}

	if added > 0 {
		log.Printf("Added %d custom certificates from %s", added, dir)
	} else {
		log.Printf("No custom certificates found in %s", dir)
	}

	return pool
}

func main() {
	cfg, err := LoadConfig("config.yml")
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range cfg.Proxies {
		log.Println("proxy:", p.URL, "blacklist:", p.Blacklist, "whitelist:", p.Whitelist)
	}
	loadCache()
	certPool = loadCerts(cfg.Server.CertPath)

	go func() {
		ticker := time.NewTicker(cfg.Cache.SaveTime)
		defer ticker.Stop()

		for {
			<-ticker.C
			saveCache()
		}
	}()

	go func() {
		ticker := time.NewTicker(cfg.Cache.CleanupInterval)
		defer ticker.Stop()

		for {
			<-ticker.C
			cacheCleanup(cfg.Cache.MaxAge)
		}
	}()

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: http.HandlerFunc(handleConnection),
	}

	log.Println("Proxy server listening on ", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port))
	log.Fatal(server.ListenAndServe())
}
