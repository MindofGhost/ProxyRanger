package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"golang.org/x/sync/errgroup"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type StatusError int

func (e StatusError) Error() string { return "" }

func dpiUploadProbe(
	ctx context.Context,
	client *http.Client,
	url string,
	host string,
	bytesTotal int,
	bytesPerChunk int,
	delay time.Duration,
) error {

	pr, pw := io.Pipe()

	req, err := http.NewRequestWithContext(ctx, "PUT", url, pr)
	if err != nil {
		return err
	}

	req.Host = host
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Expect", "100-continue")

	go func() {
		defer pw.Close()

		buf := make([]byte, bytesPerChunk)
		sent := 0

		for sent < bytesTotal {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if _, err := rand.Read(buf); err != nil {
				pw.CloseWithError(err)
				return
			}

			n, err := pw.Write(buf)
			if err != nil {
				return
			}

			sent += n
			time.Sleep(delay)
		}
	}()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	io.CopyN(io.Discard, resp.Body, 512)

	return nil
}

func makeRequest(client *http.Client, req *http.Request, proxyURL *url.URL, target, method string) (ok bool, status int) {

	resp, err := client.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) && errors.Is(err, context.DeadlineExceeded) {
			log.Printf("%s Proxy %s failed to reach %s: %v", method, proxyURL, target, err)
		}
		return false, 0
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode != 404 && resp.StatusCode != 418 {
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
func checkProxy(proxyURL *url.URL, target string, method string) (ok bool, status int) {

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
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

	if method == "PUT" {
		ctx, cancel := context.WithTimeout(context.Background(), 3000*time.Millisecond)
		defer cancel()

		err := dpiUploadProbe(
			ctx,
			client,
			"https://"+target,
			target,
			128*1024,
			16*4096,
			8*time.Millisecond,
		)

		if err != nil {
			log.Printf("PUT <DPI Detected> Remove proxy %s from check for %s. Returned error: %s", proxyURL, target, err)
			return false, 0
		}

		return true, 0
	}

	baseReq, err := http.NewRequest(method, "https://"+target, nil)
	if err != nil {
		return false, 0
	}
	baseReq.Header.Set("User-Agent", cfg.UserAgent)

	okCh := make(chan int, 1)

	g, ctx := errgroup.WithContext(context.Background())

	for attempt := 1; attempt <= cfg.DPI.RetryAttempts; attempt++ {
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

type ProbeResult struct {
	Proxy  *Proxy
	OK     bool
	Status int
}

// Запуск проверки одного proxy в горутине. Возвращаемый канал буферизованный
// и закрывается после отправки результата — потребитель читает в любой момент.
func probeAsync(proxy *Proxy, target, method string) <-chan ProbeResult {
	ch := make(chan ProbeResult, 1)
	go func() {
		ok, status := checkProxy(proxy.ParsedURL, target, method)
		ch <- ProbeResult{Proxy: proxy, OK: ok, Status: status}
		close(ch)
	}()
	return ch
}

// Параллельный запуск probeAsync для каждого proxy с ожиданием всех результатов.
// Срез возвращается в порядке входного списка proxies.
func probeAll(proxies []*Proxy, target, method string) []ProbeResult {
	chans := make([]<-chan ProbeResult, len(proxies))
	for i, p := range proxies {
		chans[i] = probeAsync(p, target, method)
	}
	out := make([]ProbeResult, len(proxies))
	for i, ch := range chans {
		out[i] = <-ch
	}
	return out
}

func proxyPtrs(ps []Proxy) []*Proxy {
	out := make([]*Proxy, len(ps))
	for i := range ps {
		out[i] = &ps[i]
	}
	return out
}

// Возвращает proxy, успешно прошедшие пробу. Если таких нет — все из all.
func survivorsOrAll(res []ProbeResult, all []Proxy) []*Proxy {
	survivors := make([]*Proxy, 0, len(res))
	for _, r := range res {
		if r.OK {
			survivors = append(survivors, r.Proxy)
		}
	}
	if len(survivors) == 0 {
		return proxyPtrs(all)
	}
	return survivors
}

func codesFrom(res []ProbeResult) []int {
	codes := make([]int, len(res))
	for i, r := range res {
		codes[i] = r.Status
	}
	return codes
}

// Эвристика «выбор по различию кодов»: если у соседних proxy разные коды
// ответа — выбираем proxy с уникальным кодом. Чистая функция.
func differenceFallback(proxies []*Proxy, codes []int) (string, bool) {
	if len(proxies) <= 1 {
		return "", false
	}
	idx := len(proxies) - 1
	for i := len(proxies) - 1; i > 0; i-- {
		if codes[i] == codes[i-1] {
			idx--
			if i != 1 || len(proxies) == len(cfg.Proxies) || (codes[i] == 403 && i == 1) {
				continue
			}
		}
		if idx != len(proxies)-1 {
			return proxies[idx].URL, true
		}
	}
	return "", false
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

	putRes := probeAll(proxyPtrs(cfg.Proxies), domain, "PUT")
	localProxies := survivorsOrAll(putRes, cfg.Proxies)

	domCh, domLoaded := getOrCreateChannel(domain)
	if !domLoaded {
		defer func() {
			close(domCh)
			inProgress.Delete(domain)
		}()

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
				checkMainDomain(mainDom, localProxies)
			}(mainDom, ch)
		}

		getRes := probeAll(localProxies, domain, "GET")
		for _, r := range getRes {
			if r.OK {
				cacheMu.Lock()
				cache[mainDom] = r.Proxy.URL
				cacheMu.Unlock()
				log.Printf("Updated proxy %s for domain %s based on working subdomain %s via GET", r.Proxy.URL, mainDom, domain)
				return r.Proxy.URL, true
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

		if pick, ok := differenceFallback(localProxies, codesFrom(getRes)); ok {
			cacheMu.Lock()
			cache[mainDom] = pick
			cacheMu.Unlock()
			log.Printf("Updated proxy %s for domain %s based on response difference", pick, mainDom)
			return pick, true
		}

	} else {
		<-domCh // ждём завершения фоновой проверки другим потоком
		cacheMu.RLock()
		if proxy, ok := cache[domain]; ok {
			cacheMu.RUnlock()
			log.Printf("Using proxy %s for %s after other stream check", proxy, domain)
			return proxy, true
		}
		cacheMu.RUnlock()
	}
	// fallback на последний
	log.Printf("All proxies failed for %s, falling back to last proxy %s", domain, cfg.Proxies[len(cfg.Proxies)-1].URL)
	return cfg.Proxies[len(cfg.Proxies)-1].URL, true
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
func checkMainDomain(mainDom string, mainDomainProxies []*Proxy) {
	log.Printf("Starting background mainDom check for %s", mainDom)

	putRes := probeAll(mainDomainProxies, mainDom, "PUT")
	localProxies := survivorsOrAll(putRes, cfg.Proxies)

	getRes := probeAll(localProxies, mainDom, "GET")
	for _, r := range getRes {
		if r.OK {
			cacheMu.Lock()
			cache[mainDom] = r.Proxy.URL
			cacheMu.Unlock()
			log.Printf("Selected proxy %s for domain %s and all its subdomains via GET", r.Proxy.URL, mainDom)
			return
		}
	}

	if pick, ok := differenceFallback(localProxies, codesFrom(getRes)); ok {
		cacheMu.Lock()
		cache[mainDom] = pick
		cacheMu.Unlock()
		log.Printf("Updated proxy %s for domain %s and all its subdomains based on response difference", pick, mainDom)
	}
}
