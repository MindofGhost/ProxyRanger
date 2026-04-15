package main

import (
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	cache      = make(map[string]string) // main domain -> upstream proxy
	userCache  = make(map[string]string)
	cacheMu    sync.RWMutex
	inProgress sync.Map // key: mainDom, value: chan struct{}
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

// Сохраняем кэш на диск
func saveCache() {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	f, err := os.Create(cfg.Server.CacheFile)
	if err != nil {
		log.Println("Failed to save cache:", err)
		return
	}
	defer f.Close()
	json.NewEncoder(f).Encode(cache)
}

// Загружаем кэш с диска
func loadCache() {
	f, err := os.Open(cfg.Server.CacheFile)
	if err != nil {
		log.Println("No cache file found, starting fresh")
	} else {
		defer f.Close()
		json.NewDecoder(f).Decode(&cache)
		log.Println("Loaded cache from disk")
	}

	uf, err := os.Open(cfg.Server.UserCacheFile)
	if err != nil {
		log.Println("user.json not found, skipping")
		return
	}
	defer uf.Close()

	if err := json.NewDecoder(uf).Decode(&userCache); err != nil {
		log.Printf("Failed to decode user.json: %v", err)
		return
	}

	// Объединяем: данные из user.json имеют приоритет
	for k, v := range userCache {
		cache[k] = v
	}

	log.Printf("Cache loaded. Total entries after merging: %d", len(cache))

}

func main() {
	cfg, err := LoadConfig("config.yml")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("methods:", cfg.Server.CheckMethods)
	for _, p := range cfg.Proxies {
		log.Println("proxy:", p.URL, "blacklist:", p.Blacklist)
	}
	loadCache()
	certPool = loadCerts(cfg.Server.CertPath)

	go func() {
		for {
			time.Sleep(time.Duration(cfg.Server.CacheSaveTimeSec) * time.Second)
			saveCache()
		}
	}()

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: http.HandlerFunc(handleConnection),
	}

	log.Println("Proxy server listening on ", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port))
	log.Fatal(server.ListenAndServe())
}
