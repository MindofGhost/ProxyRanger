package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
	"golang.org/x/sync/errgroup"
)

type StatusError int

type ProxyResult struct {
	Proxy  *Proxy
	Status int
	OK     bool
	Bytes  int64
	Speed  float64

	Ready chan struct{}
}

type inflightEntry struct {
	ch      chan struct{}
	running bool
}

func (e StatusError) Error() string { return "" }

type CheckResult struct {
	OK     bool
	Status int
	Bytes  int64
	Speed  float64
}

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

	req, err := http.NewRequestWithContext(ctx, "POST", url, pr)
	if err != nil {
		return err
	}

	req.Host = host
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://"+host)
	req.Header.Set("Referer", "https://"+host+"/")
	// req.Header.Set("Expect", "100-continue")
	req.ContentLength = int64(bytesTotal)

	go func() {
		defer pw.Close()

		payload := []byte("data=" + strings.Repeat("a", bytesPerChunk-5))
		sent := 0

		for sent < bytesTotal {
			select {
			case <-ctx.Done():
				return
			default:
			}
			remaining := bytesTotal - sent
			chunk := payload
			if remaining < len(payload) {
				chunk = payload[:remaining]
			}

			n, err := pw.Write(chunk)
			if err != nil {
				return
			}

			sent += n
			time.Sleep(delay + time.Duration(rand.Intn(100))*time.Millisecond)
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

func makeRequest(client *http.Client, req *http.Request, proxyURL *url.URL, target, method string) CheckResult {

	start := time.Now()
	var firstByteTime time.Time

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			firstByteTime = time.Now()
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	res := CheckResult{}

	resp, err := client.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) && errors.Is(err, context.DeadlineExceeded) {
			log.Printf("%s Proxy %s failed to reach %s: %v", method, proxyURL, target, err)
		}
		return res
	}
	defer resp.Body.Close()

	res.Status = resp.StatusCode

	if resp.StatusCode >= 400 && resp.StatusCode != 404 && resp.StatusCode != 418 {
		log.Printf("%s Proxy %s returned bad status %d for %s", method, proxyURL, resp.StatusCode, target)
		return res
	}

	// --- ЧИТАЕМ ВСЁ ТЕЛО ---
	n, readErr := io.Copy(io.Discard, resp.Body)
	totalTime := time.Since(start)

	res.Bytes = n

	// TTFB (оставлено для логов)
	var ttfb time.Duration
	if !firstByteTime.IsZero() {
		ttfb = firstByteTime.Sub(start)
	}

	if readErr != nil {
		log.Printf("%s Proxy %s body read error for %s: %v (bytes=%d, time=%s, ttfb=%s)",
			method, proxyURL, target, readErr, n, totalTime, ttfb)
		return res
	}

	// Проверка полной доставки
	if method != "HEAD" && resp.ContentLength > 0 && n != resp.ContentLength {
		log.Printf("%s Proxy %s returned only %d bytes instead of %d for %s. Bad proxy or DPI detected",
			method, proxyURL, n, resp.ContentLength, target)
		return res
	}

	// Скорость
	if totalTime > 0 {
		res.Speed = float64(n) / totalTime.Seconds()
	}
	if n < 30000 {
		return res
	}

	log.Printf("%s Proxy %s OK %s | bytes=%d | time=%s | ttfb=%s | speed=%.2f KB/s",
		method, proxyURL, target, n, totalTime, ttfb, res.Speed/1024)

	res.OK = true
	return res
}

// Проверка доступности прокси через target
func checkProxy(ctx context.Context, proxyURL *url.URL, target string, method string) CheckResult {

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

	if method == "POST" {
		ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Timeouts.CheckProxy.Timeout)*time.Millisecond)
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
				return CheckResult{OK: true}
			}

			if strings.Contains(err.Error(), "use of closed network connection") {
				return CheckResult{OK: true}
			}
			log.Printf("POST <DPI Detected> Remove proxy %s from check for %s. Returned error: %s", proxyURL, target, err)
			return CheckResult{}
		}

		return CheckResult{OK: true}
	}

	baseReq, err := http.NewRequestWithContext(ctx, method, "https://"+target, nil)
	if err != nil {
		return CheckResult{}
	}
	baseReq.Header.Set("User-Agent", cfg.UserAgent)
	baseReq.Header.Set("Accept", "*/*")
	baseReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	baseReq.Header.Set("Origin", "https://"+target)
	baseReq.Header.Set("Referer", "https://"+target+"/")
	okCh := make(chan CheckResult, 1)
	lastCh := make(chan CheckResult, cfg.DPI.RetryAttempts)
	g, ctx := errgroup.WithContext(ctx)

	for attempt := 1; attempt <= cfg.DPI.RetryAttempts; attempt++ {
		g.Go(func() error {
			req := baseReq.Clone(ctx)

			res := makeRequest(client, req, proxyURL, target, method)

			select {
			case lastCh <- res:
			default:
			}
			if !res.OK {
				return StatusError(res.Status)
			}

			select {
			case okCh <- res:
			default:
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {

		close(lastCh)
		var last CheckResult
		for r := range lastCh {
			last = r
		}

		if last.Status == 0 {
			if se, ok := err.(StatusError); ok {
				last.Status = int(se)
			}
		}

		return last
	}

	res := <-okCh
	return res
}

func checkProxyAsync(ctx context.Context, p *Proxy, domain string, method string) *ProxyResult {
	res := &ProxyResult{
		Proxy: p,
		Ready: make(chan struct{}),
	}

	go func() {
		r := checkProxy(ctx, p.ParsedURL, domain, method)

		res.OK = r.OK
		res.Status = r.Status
		res.Bytes = r.Bytes
		res.Speed = r.Speed
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
			go runCheckSubdomain(mainDom, res.Value, proxies)
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

func filterProxies(domain string, proxies []*Proxy, blacklist bool) []*Proxy {
	filtered := make([]*Proxy, 0, len(proxies))

	for _, p := range proxies {
		if p == nil {
			continue
		}

		skip := false
		if !blacklist {
			skip = true
			for _, re := range p.whitecompiled {
				if re.MatchString(domain) {
					log.Printf("Proxy %s added for priority check %s (whitelist match: %s)", p.URL, domain, re.String())
					skip = false
					break
				}
			}
		}

		if !skip {
			for _, re := range p.blackcompiled {
				if re.MatchString(domain) {
					log.Printf("Proxy %s skipped for domain %s (blacklist match: %s)", p.URL, domain, re.String())
					skip = true
					break
				}
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
	WLProxies := filterProxies(domain, proxies, false)
	proxies = filterProxies(domain, proxies, true)
	ch, loaded := getOrCreateChannel(domain)

	if !loaded {
		go func() {
			defer closeChannel(domain)
			log.Printf("Run check for domain %s", domain)
			if len(WLProxies) > 0 {
				checkDomain(domain, WLProxies)
			}
			if res := cacheGet(domain); (!res.Found || res.Expired) && len(WLProxies) != len(proxies) {
				checkDomain(domain, proxies)
			}
		}()
	}

	return ch
}

func runCheckSubdomain(domain string, proxy string, proxies []*Proxy) {
	proxies = filterProxies(domain, proxies, true)
	for _, p := range proxies {
		if p.URL == proxy {
			<-runCheck(domain, []*Proxy{p})
			break
		}
	}
	if res := cacheGet(domain); res.Found && !res.Expired {
		return
	}
	<-runCheck(domain, proxies)
}

// Функция проверки домена
func checkDomain(domain string, proxies []*Proxy) {
	localProxies := make([]*Proxy, 0, len(proxies))
	resultsHEAD := make([]*ProxyResult, 0, len(proxies))
	results := make([]*ProxyResult, 0, len(proxies))
	resultsGET := make([]*ProxyResult, 0, len(proxies))
	// ctx := context.WithoutCancel(context.Background())
	// if cfg.DPI.UsePOSTinRechecks || len(proxies) > 1 {
	// 	log.Printf("Start POST check for domain %s", domain)
	// 	for _, proxy := range proxies {
	// 		results = append(results, checkProxyAsync(ctx, proxy, domain, "POST"))
	// 	}
	// 	for _, r := range results {
	// 		<-r.Ready
	// 		if r.OK {
	// 			localProxies = append(localProxies, r.Proxy)
	// 		}
	// 	}
	// } else {
	localProxies = proxies
	// }

	// if len(localProxies) == 0 {
	// 	if len(proxies) > 1 {
	// 		log.Printf("All proxy for domain %s failed in full check. Return proxies back", domain)
	// 		localProxies = proxies
	// 	} else {
	// 		log.Printf("All proxy for domain %s failed", domain)
	// 		return
	// 	}
	// }

	log.Printf("Start HEAD check for domain %s", domain)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, proxy := range localProxies {
		resultsHEAD = append(resultsHEAD, checkProxyAsync(ctx, proxy, domain, "HEAD"))
	}
	for _, r := range resultsHEAD {
		<-r.Ready
		if r.OK {
			cancel()
			cacheSet(domain, r.Proxy.URL)
			log.Printf("Selected proxy %s for domain %s via HEAD", r.Proxy.URL, domain)
			return
		}
	}

	// 2. Если все HEAD провалились - пробуем GET
	log.Printf("Start GET check for domain %s", domain)
	for _, proxy := range localProxies {
		resultsGET = append(resultsGET, checkProxyAsync(ctx, proxy, domain, "GET"))
	}
	for _, r := range resultsGET {
		<-r.Ready
		if r.OK {
			cancel()
			cacheSet(domain, r.Proxy.URL)
			log.Printf("Selected proxy %s for domain %s via GET", r.Proxy.URL, domain)
			return
		}
	}

	if len(localProxies) > 1 {
		idx := len(localProxies) - 1
		errorReturns := 0
		var workingProxyID int
		for i, v := range resultsGET {
			if v.Status == 0 {
				errorReturns++
			} else {
				workingProxyID = i
			}
		}
		if errorReturns == len(localProxies)-1 {
			cacheSet(domain, localProxies[workingProxyID].URL)
			log.Printf("Updated proxy %s for domain %s as its only one working proxy", localProxies[workingProxyID].URL, domain)
			return
		}
		errorReturns = 0
		for i, v := range resultsHEAD {
			if v.Status == 0 {
				errorReturns++
			} else {
				workingProxyID = i
			}
		}
		if errorReturns == len(localProxies)-1 {
			cacheSet(domain, localProxies[workingProxyID].URL)
			log.Printf("Updated proxy %s for domain %s as its only one working proxy", localProxies[workingProxyID].URL, domain)
			return
		}
		for i := len(localProxies) - 1; i > 0; i-- {
			if resultsGET[i].Status == resultsGET[i-1].Status {
				idx--
				if i != 1 || len(localProxies) == len(cfg.Proxies) || (resultsGET[i].Status == 403 && i == 1 && len(localProxies) > 2) {
					continue
				}
			}
			if idx != len(localProxies)-1 {
				cacheSet(domain, localProxies[idx].URL)
				log.Printf("Updated proxy %s for domain %s based on GET response difference", localProxies[idx].URL, domain)
				return
			}
		}
		idx = len(localProxies) - 1
		for i := len(localProxies) - 1; i > 0; i-- {
			if resultsHEAD[i].Status == resultsHEAD[i-1].Status {
				idx--
				if i != 1 || len(localProxies) == len(cfg.Proxies) || (resultsHEAD[i].Status == 403 && i == 1 && len(localProxies) > 2) {
					continue
				}
			}
			if idx != len(localProxies)-1 {
				cacheSet(domain, localProxies[idx].URL)
				log.Printf("Updated proxy %s for domain %s based on HEAD response difference", localProxies[idx].URL, domain)
				return
			}
		}
	}

	if cfg.DPI.UsePOSTinRechecks || len(proxies) > 1 {
		log.Printf("Start POST check for domain %s", domain)
		for _, proxy := range proxies {
			results = append(results, checkProxyAsync(ctx, proxy, domain, "POST"))
		}
		for _, r := range results {
			<-r.Ready
			if r.OK {
				cancel()
				cacheSet(domain, r.Proxy.URL)
				log.Printf("Selected proxy %s for domain %s via POST", r.Proxy.URL, domain)
				return
			}
		}
	}
	mainDom := mainDomain(domain)
	if len(proxies) != 1 {
		if res := cacheGet(mainDom); res.Found {
			cacheSet(domain, res.Value)
			log.Printf("Updated proxy %s for domain %s based on mainDomain", res.Value, domain)
			return
		}
	}

}
