package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"time"
)

type CacheResult struct {
	Value   string
	Found   bool
	Expired bool
}

func cacheSet(key, value string) {
	cacheMu.Lock()
	cache[key] = CacheEntry{
		Value:     value,
		CreatedAt: time.Now(),
	}
	cacheMu.Unlock()
}

func cacheGet(key string) CacheResult {
	cacheMu.RLock()
	entry, ok := cache[key]
	cacheMu.RUnlock()

	if !ok {
		return CacheResult{}
	}

	return CacheResult{
		Value:   entry.Value,
		Found:   true,
		Expired: time.Since(entry.CreatedAt) > cfg.Cache.TTL,
	}
}

// Загружаем кэш с диска
func loadCache() {
	// 👇 ВСЕГДА инициализируем
	cache = make(map[string]CacheEntry)

	// --- основной cache ---
	f, err := os.Open(cfg.Server.CacheFile)
	if err != nil {
		log.Println("No cache file found, starting fresh")
	} else {
		defer f.Close()

		if err := json.NewDecoder(f).Decode(&cache); err != nil {
			if err != io.EOF {
				log.Printf("Failed to decode cache.json: %v", err)
			}
			// если файл пустой или битый — просто продолжаем с пустым cache
			cache = make(map[string]CacheEntry)
		} else {
			log.Printf("Loaded cache from disk: %d entries", len(cache))
		}
	}

	// --- user cache ---
	uf, err := os.Open(cfg.Server.UserCacheFile)
	if err != nil {
		log.Println("user.json not found, skipping")
		return
	}
	defer uf.Close()

	userCache := make(map[string]string)

	if err := json.NewDecoder(uf).Decode(&userCache); err != nil {
		log.Printf("Failed to decode user.json: %v", err)
		return
	}

	// --- merge ---
	for k, v := range userCache {
		cache[k] = CacheEntry{
			Value:     v,
			CreatedAt: time.Unix(1<<62, 0), // "вечная" запись
		}
	}

	log.Printf("Cache loaded. Total entries after merging: %d", len(cache))
}

// Сохраняем кэш на диск
func saveCache() {
	cacheMu.RLock()
	defer cacheMu.RUnlock()

	if len(cache) == 0 {
		log.Println("Skip saving empty cache")
		return
	}

	log.Printf("Saving cache: %d entries", len(cache))

	f, err := os.Create(cfg.Server.CacheFile)
	if err != nil {
		log.Println("Failed to save cache:", err)
		return
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(cache); err != nil {
		log.Println("Failed to encode cache:", err)
	}
}

func cacheCleanup(maxAge time.Duration) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	newCache := make(map[string]CacheEntry, len(cache))

	for k, v := range cache {
		// 👇 "вечные" записи не трогаем
		if v.CreatedAt.After(time.Now()) {
			newCache[k] = v
			continue
		}

		if time.Since(v.CreatedAt) <= maxAge {
			newCache[k] = v
		}
	}

	log.Printf("Cache cleanup: before=%d after=%d", len(cache), len(newCache))

	cache = newCache
}
