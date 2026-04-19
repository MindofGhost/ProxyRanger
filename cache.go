package main

import (
	"encoding/json"
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
		cache[k] = CacheEntry{
			Value:     v,
			CreatedAt: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), // или другое время
		}
	}

	log.Printf("Cache loaded. Total entries after merging: %d", len(cache))

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

func cacheCleanup(maxAge time.Duration) {
	cacheMu.Lock()

	newCache := make(map[string]CacheEntry, len(cache))
	for k, v := range cache {
		if time.Since(v.CreatedAt) <= maxAge {
			newCache[k] = v
		}
	}

	cache = newCache
	cacheMu.Unlock()
}
