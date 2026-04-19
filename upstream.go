package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"golang.org/x/net/publicsuffix"
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

type ProxyResult struct {
	Proxy  *Proxy
	Status int
	OK     bool

	Ready chan struct{}
}

type inflightEntry struct {
	ch      chan struct{}
	running bool
}

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
	// req.Header.Set("Expect", "100-continue")
	req.ContentLength = int64(bytesTotal)

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
func checkProxy(ctx context.Context, proxyURL *url.URL, target string, method string) (ok bool, status int) {

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: time.Duration(cfg.Timeouts.CheckProxy.DialContext) * time.Millisecond,
			}).DialContext,
			TLSHandshakeTimeout:   time.Duration(cfg.Timeouts.CheckProxy.TLSHandshakeTimeout) * time.Millisecond,
			ResponseHeaderTimeout: time.Duration(cfg.Timeouts.CheckProxy.ResponseHeaderTimeout) * time.Millisecond,
			ExpectContinueTimeout: time.Duration(cfg.Timeouts.CheckProxy.ExpectContinueTimeout) * time.Millisecond,
			DisableCompression:    true,
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: time.Duration(cfg.Timeouts.CheckProxy.Timeout) * time.Millisecond,
	}

	if method == "PUT" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeouts.CheckProxy.Timeout)*time.Millisecond)
		defer cancel()

		err := dpiUploadProbe(
			ctx,
			client,
			"https://"+target,
			target,
			cfg.DPI.UploadProbe.TotalSizeKB,
			cfg.DPI.UploadProbe.ChunkSizeKB,
			time.Duration(cfg.DPI.UploadProbe.DelayMS)*time.Millisecond,
		)

		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return true, 0
			}

			if strings.Contains(err.Error(), "use of closed network connection") {
				return true, 0
			}
			log.Printf("PUT <DPI Detected> Remove proxy %s from check for %s. Returned error: %s", proxyURL, target, err)
			return false, 0
		}

		return true, 0
	}

	baseReq, err := http.NewRequestWithContext(ctx, method, "https://"+target, nil)
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

func checkProxyAsync(ctx context.Context, p *Proxy, domain string, method string) *ProxyResult {
	res := &ProxyResult{
		Proxy: p,
		Ready: make(chan struct{}),
	}

	go func() {
		res.OK, res.Status = checkProxy(ctx, p.ParsedURL, domain, method)
		close(res.Ready)
	}()

	return res
}

// Получаем основной домен из хоста (например, sub.example.com -> example.com, sub.example.co.uk -> example.co.uk)
func mainDomain(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	mainDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return mainDomain
}

// Ищем рабочий апстрим для домена и кэшируем для всех поддоменов
func findWorkingProxy(domain string) (string, bool) {
	mainDom := mainDomain(domain)
	proxies := make([]*Proxy, len(cfg.Proxies))
	for i := range cfg.Proxies {
		proxies[i] = &cfg.Proxies[i]
	}
	// --- Проверяем кэш ---
	res := cacheGet(domain)
	resMain := cacheGet(mainDom)
	defer func() {
		if res.Expired {
			go runCheckSubdomain(domain, res.Value, proxies)
		}
		if resMain.Expired && domain != mainDom {
			go runCheckSubdomain(domain, res.Value, proxies)
		}
	}()
	if res.Found && resMain.Found {
		return res.Value, true
	}
	if res.Found && !resMain.Found {
		cacheSet(mainDom, res.Value)
		return res.Value, true
	}
	if !res.Found && resMain.Found {
		go runCheckSubdomain(domain, resMain.Value, proxies)
		return resMain.Value, true
	}
	if !res.Found && !resMain.Found {
		if domain != mainDom {
			chMain := runCheck(mainDom, proxies)
			ch := runCheck(domain, proxies)
			<-chMain
			<-ch
		} else {
			ch := runCheck(domain, proxies)
			<-ch
		}
		if res := cacheGet(domain); res.Found {
			return res.Value, true
		}

		if res := cacheGet(mainDom); res.Found {
			return res.Value, true
		}
	}
	// fallback на последний
	log.Printf("All proxies failed for %s, falling back to last proxy %s", domain, cfg.Proxies[len(cfg.Proxies)-1].URL)
	return cfg.Proxies[len(cfg.Proxies)-1].URL, true
}

// Функция проверки канала
func getOrCreateChannel(domain string) (chan struct{}, bool) {
	if domain == "" {
		ch := make(chan struct{})
		close(ch)
		return ch, true
	}

	newEntry := &inflightEntry{
		ch:      make(chan struct{}),
		running: true,
	}

	actual, loaded := inProgress.LoadOrStore(domain, newEntry)

	entry := actual.(*inflightEntry)

	return entry.ch, loaded
}

func closeChannel(domain string) {
	if domain == "" {
		return
	}

	val, ok := inProgress.Load(domain)
	if !ok {
		return
	}

	entry := val.(*inflightEntry)

	if inProgress.CompareAndDelete(domain, entry) {
		close(entry.ch)
	}
}

func filterProxies(domain string, proxies []*Proxy) []*Proxy {
	filtered := make([]*Proxy, 0, len(proxies))

	for _, p := range proxies {
		if p == nil {
			continue
		}

		skip := false
		for _, re := range p.compiled {
			if re.MatchString(domain) {
				log.Printf("Proxy %s skipped for domain %s (blacklist match: %s)", p.URL, domain, re.String())
				skip = true
				break
			}
		}

		if skip {
			continue
		}

		filtered = append(filtered, p)
	}

	return filtered
}

func runCheck(domain string, proxies []*Proxy) chan struct{} {
	proxies = filterProxies(domain, proxies)
	ch, loaded := getOrCreateChannel(domain)

	if !loaded {
		go func() {
			defer closeChannel(domain)
			checkDomain(domain, proxies)
		}()
	}

	return ch
}

func runCheckSubdomain(domain string, proxy string, proxies []*Proxy) {
	proxies = filterProxies(domain, proxies)
	for _, p := range proxies {
		if p.URL == proxy {
			<-runCheck(domain, []*Proxy{p})

			if res := cacheGet(domain); res.Found {
				return
			}
			break
		}
	}
	<-runCheck(domain, proxies)
}

// Функция проверки домена
func checkDomain(domain string, proxies []*Proxy) {
	localProxies := make([]*Proxy, 0, len(proxies))
	results := make([]*ProxyResult, 0, len(proxies))
	ctx := context.WithoutCancel(context.Background())
	for _, proxy := range proxies {
		results = append(results, checkProxyAsync(ctx, proxy, domain, "PUT"))
	}
	for _, r := range results {
		<-r.Ready
		if r.OK {
			localProxies = append(localProxies, r.Proxy)
		}
	}

	if len(localProxies) == 0 {
		localProxies = proxies
	}
	// Проверяем основной домен
	// for _, proxy := range localProxies {
	// 	if ok, _ := checkProxy(proxy, mainDom, "HEAD"); ok {
	// 		cacheMu.Lock()
	// 		cache[mainDom] = proxy
	// 		cacheMu.Unlock()
	// 		log.Printf("Selected proxy %s for domain %s and all its subdomains via HEAD", proxy, mainDom)
	// 		return
	// 	}
	// }
	codes := make([]int, len(localProxies))

	// 2. Если все HEAD провалились - пробуем GET
	results = make([]*ProxyResult, 0, len(localProxies))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, proxy := range localProxies {
		results = append(results, checkProxyAsync(ctx, proxy, domain, "GET"))
	}
	for i, r := range results {
		<-r.Ready
		codes[i] = r.Status
		if r.OK {
			cancel()
			cacheSet(domain, r.Proxy.URL)
			log.Printf("Selected proxy %s for domain %s via GET", r.Proxy.URL, domain)
			return
		}
	}

	if len(localProxies) > 1 {
		idx := len(localProxies) - 1
		for i := len(localProxies) - 1; i > 0; i-- {
			if codes[i] == codes[i-1] {
				idx--
				if i != 1 || len(localProxies) == len(cfg.Proxies) || (codes[i] == 403 && i == 1) {
					continue
				}
			}
			if idx != len(localProxies)-1 {
				cacheSet(domain, localProxies[idx].URL)
				log.Printf("Updated proxy %s for domain %s based on response difference", localProxies[idx].URL, domain)
				return
			}
		}
	}
	mainDom := mainDomain(domain)
	if domain != mainDom && len(proxies) != 1 {
		if res := cacheGet(mainDom); res.Found {
			cacheSet(domain, res.Value)
			log.Printf("Updated proxy %s for domain %s based on mainDomain", res.Value, domain)
			return
		}
	}

}
