package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	proxies       []string
	cache         = make(map[string]string) // main domain -> upstream proxy
	userCache     = make(map[string]string)
	cacheMu       sync.RWMutex
	cacheFile     = "cache/cache.json"
	userCacheFile = "cache/user.json"
	inProgress    sync.Map // key: mainDom, value: chan struct{}
	certPool      *x509.CertPool
	certPath      = "certs"
)

const (
	minBodyLength      = 1000
	checkRetryAttempts = 10
	chromeUA           = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

type StatusError int

func (e StatusError) Error() string { return "" }

// LoadCertPoolFromDir load custom certs from ./certs
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

// Загружаем список апстрим-прокси из файла
func loadProxies(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Cannot open %s: %v", filename, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}
	log.Printf("Loaded %d upstream proxies", len(proxies))
}

// Сохраняем кэш на диск
func saveCache() {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	f, err := os.Create(cacheFile)
	if err != nil {
		log.Println("Failed to save cache:", err)
		return
	}
	defer f.Close()
	json.NewEncoder(f).Encode(cache)
}

// Загружаем кэш с диска
func loadCache() {
	f, err := os.Open(cacheFile)
	if err != nil {
		log.Println("No cache file found, starting fresh")
	} else {
		defer f.Close()
		json.NewDecoder(f).Decode(&cache)
		log.Println("Loaded cache from disk")
	}

	uf, err := os.Open(userCacheFile)
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

func makeRequest(client *http.Client, req *http.Request, proxyURL, target, method string) (ok bool, status int) {

	resp, err := client.Do(req)
	if err != nil {
		if !(errors.Is(err, context.Canceled) || !errors.Is(err, context.DeadlineExceeded)) {
			log.Printf("%s Proxy %s failed to reach %s: %v", method, proxyURL, target, err)
		}
		return false, 0
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode != 404 {
		log.Printf("%s Proxy %s returned bad status %d for %s", method, proxyURL, resp.StatusCode, target)
		return false, resp.StatusCode
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("%s Proxy %s read body failed: %v for %s", method, proxyURL, err, target)
		return false, 0
	}

	if method != "HEAD" && resp.ContentLength > 0 && int64(len(body)) != resp.ContentLength {
		log.Printf("%s Proxy %s returned only %d bytes instead of %d for %s. Bad proxy or DPI detected", method, proxyURL, int64(len(body)), resp.ContentLength, target)
		return false, 0
	}

	return true, resp.StatusCode
}

// Проверка доступности прокси через target
func checkProxy(proxyURL string, target string, method string) (ok bool, status int) {
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return false, 0
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
			DialContext: (&net.Dialer{
				Timeout: 1 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   1800 * time.Millisecond,
			ResponseHeaderTimeout: 2500 * time.Millisecond,
			ExpectContinueTimeout: 500 * time.Millisecond,
			DisableCompression:    true,
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: 3000 * time.Millisecond,
	}

	baseReq, err := http.NewRequest(method, "https://"+target, nil)
	if err != nil {
		return false, 0
	}
	baseReq.Header.Set("User-Agent", chromeUA)

	okCh := make(chan int, 1)

	g, ctx := errgroup.WithContext(context.Background())

	for attempt := 1; attempt <= checkRetryAttempts; attempt++ {
		g.Go(func() error {
			req := baseReq.Clone(ctx)

			ok, status := makeRequest(client, req, proxyURL, target, method)

			if !ok {
				return StatusError(status)
			}

			select {
			case okCh <- status:
			default:
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {

		if se, ok := err.(StatusError); ok {
			return false, int(se)
		}
		return false, 0
	}

	status = <-okCh
	return true, status
}

// Получаем основной домен из хоста (например, sub.example.com -> example.com)
func mainDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

// Ищем рабочий апстрим для домена и кэшируем для всех поддоменов
func findWorkingProxy(domain string) (string, bool) {
	mainDom := mainDomain(domain)
	// --- Проверяем кэш ---
	cacheMu.RLock()
	if proxy, ok := cache[mainDom]; ok {
		cacheMu.RUnlock()
		return proxy, true
	}
	cacheMu.RUnlock()
	chNeeded := domain != mainDom && net.ParseIP(domain) == nil
	ch, loaded := getOrCreateChannel(func() string {
		if chNeeded {
			return mainDom
		} else {
			return ""
		}
	}())
	if chNeeded && !loaded {
		// Мы первые - запускаем проверку mainDom в фоне
		go func(mainDom string, ch chan struct{}) {
			defer func() {
				close(ch)
				inProgress.Delete(mainDom)
			}()
			checkMainDomain(mainDom)
		}(mainDom, ch)
	}

	var lastProxy string
	if len(proxies) > 0 {
		lastProxy = proxies[len(proxies)-1]
	}

	// Проверяем апстримы для поддомена
	// for _, proxy := range proxies {
	// 	if ok, _ := checkProxy(proxy, domain, "HEAD"); ok {
	// 		cacheMu.Lock()
	// 		cache[mainDom] = proxy
	// 		cacheMu.Unlock()
	// 		log.Printf("Updated proxy %s for domain %s based on working subdomain %s via HEAD", proxy, mainDom, domain)
	// 		return proxy, true
	// 	}
	// }

	// Если все HEAD провалились - пробуем GET
	codes := make([]int, len(proxies))
	for i, proxy := range proxies {
		ok, code := checkProxy(proxy, domain, "GET")
		codes[i] = code
		if ok {
			cacheMu.Lock()
			cache[mainDom] = proxy
			cacheMu.Unlock()
			log.Printf("Updated proxy %s for domain %s based on working subdomain %s via GET", proxy, mainDom, domain)
			return proxy, true
		}
	}

	if chNeeded {
		log.Printf("No working subdomain proxy for %s, waiting for mainDom check...", domain)
	}
	<-ch // ждём завершения фоновой проверки mainDom
	if chNeeded {
		cacheMu.RLock()
		if proxy, ok := cache[mainDom]; ok {
			cacheMu.RUnlock()
			log.Printf("Using proxy %s for %s after mainDom check", proxy, domain)
			return proxy, true
		}
		cacheMu.RUnlock()
	}

	if lastProxy != "" {
		for i := len(proxies) - 2; i >= 0; i-- {
			if codes[i] != codes[len(proxies)-1] {
				cacheMu.Lock()
				cache[mainDom] = proxies[i+1]
				cacheMu.Unlock()
				log.Printf("Updated proxy %s for domain %s based on response difference", proxies[i+1], mainDom)
				return proxies[i+1], true
			}
		}
		// fallback на последний
		log.Printf("All proxies failed for %s, falling back to last proxy %s", domain, lastProxy)
		return lastProxy, true
	}

	return "", false
}

// Функция проверки канала
func getOrCreateChannel(mainDom string) (chan struct{}, bool) {
	if mainDom == "" {
		ch := make(chan struct{})
		close(ch)
		return ch, true
	}
	ch := make(chan struct{})
	actual, loaded := inProgress.LoadOrStore(mainDom, ch)
	return actual.(chan struct{}), loaded
}

// Функция проверки главного домена
func checkMainDomain(mainDom string) {
	log.Printf("Starting background mainDom check for %s", mainDom)
	var lastProxy string
	if len(proxies) > 0 {
		lastProxy = proxies[len(proxies)-1]
	}
	// Проверяем основной домен
	// for _, proxy := range proxies {
	// 	if ok, _ := checkProxy(proxy, mainDom, "HEAD"); ok {
	// 		cacheMu.Lock()
	// 		cache[mainDom] = proxy
	// 		cacheMu.Unlock()
	// 		log.Printf("Selected proxy %s for domain %s and all its subdomains via HEAD", proxy, mainDom)
	// 		return
	// 	}
	// }
	codes := make([]int, len(proxies))

	// 2. Если все HEAD провалились - пробуем GET
	for i, proxy := range proxies {
		ok, code := checkProxy(proxy, mainDom, "GET")
		codes[i] = code
		if ok {
			cacheMu.Lock()
			cache[mainDom] = proxy
			cacheMu.Unlock()
			log.Printf("Selected proxy %s for domain %s and all its subdomains via GET", proxy, mainDom)
			return
		}
	}
	if lastProxy != "" {
		for i := len(proxies) - 2; i >= 0; i-- {
			if codes[i] != codes[len(proxies)-1] {
				cacheMu.Lock()
				cache[mainDom] = proxies[i+1]
				cacheMu.Unlock()
				log.Printf("Updated proxy %s for domain %s and all its subdomains based on response difference", proxies[i+1], mainDom)
				return
			}
		}
	}
}

// Копируем заголовки
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Основной обработчик HTTP и HTTPS
func handleConnection(w http.ResponseWriter, r *http.Request) {
	log.Printf("Incoming request: %s %s Host: %s\n", r.Method, r.URL, r.Host)

	if r.Method == http.MethodConnect {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}

		clientConn, _, err := hj.Hijack()
		if err != nil {
			log.Println("Hijack error:", err)
			return
		}

		target := r.Host
		if !strings.Contains(target, ":") {
			target += ":443"
		}
		domain := strings.Split(r.Host, ":")[0]

		upstream, ok := findWorkingProxy(domain)
		if !ok {
			log.Printf("No working proxy found for %s", domain)
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			clientConn.Close()
			return
		}

		upURL, _ := url.Parse(upstream)
		dialer := net.Dialer{Timeout: 15 * time.Second}
		conn, err := dialer.Dial("tcp", upURL.Host)
		if err != nil {
			log.Printf("Dial upstream error: %v", err)
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			clientConn.Close()
			return
		}

		// CONNECT к upstream
		connectReq := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			log.Printf("Upstream write error: %v", err)
			clientConn.Close()
			conn.Close()
			return
		}

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, r)
		if err != nil {
			log.Printf("Upstream CONNECT read error: %v", err)
			clientConn.Close()
			conn.Close()
			return
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Printf("Upstream refused CONNECT (status %d)", resp.StatusCode)
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			clientConn.Close()
			conn.Close()
			return
		}

		// Отправляем клиенту успешное подтверждение
		clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		log.Printf("Tunnel established via %s to %s", upstream, target)

		// Idle timeout контроль
		idleTimeout := 60 * time.Second
		lastActivity := time.Now()
		activity := make(chan struct{}, 1)

		// Функция для обновления активности
		updateActivity := func() {
			select {
			case activity <- struct{}{}:
			default:
			}
		}

		// Безопасный goroutine для копирования данных client -> upstream
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := clientConn.Read(buf)
				if n > 0 {
					_, _ = conn.Write(buf[:n])
					updateActivity()
				}
				if err != nil {
					conn.Close()
					clientConn.Close()
					return
				}
			}
		}()

		// Основной поток: upstream -> client
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				_, _ = clientConn.Write(buf[:n])
				lastActivity = time.Now()
			}
			if err != nil {
				break
			}

			select {
			case <-activity:
				lastActivity = time.Now()
			default:
			}

			// Проверка на бездействие
			if time.Since(lastActivity) > idleTimeout {
				log.Printf("Closing idle tunnel %s after %v inactivity", target, idleTimeout)
				break
			}
		}

		conn.Close()
		clientConn.Close()
		log.Printf("Tunnel closed for %s", target)
		return
	}
	// HTTP GET/POST
	domain := r.URL.Hostname()
	upstream, ok := findWorkingProxy(domain)
	if !ok {
		http.Error(w, "No proxy available", http.StatusBadGateway)
		return
	}

	proxyURL, _ := url.Parse(upstream)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header = r.Header

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	loadProxies("proxies.txt")
	loadCache()
	certPool = loadCerts(certPath)

	// Сохраняем кэш каждые 5 минут
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			saveCache()
		}
	}()

	server := &http.Server{
		Addr:    ":9990",
		Handler: http.HandlerFunc(handleConnection),
	}

	log.Println("Proxy server listening on :9990")
	log.Fatal(server.ListenAndServe())
}
