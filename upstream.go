package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
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
	proxyURL *url.URL,
	target string,
	bytesTotal int,
	bytesPerChunk int,
	delay time.Duration,
) (err error) {
	bytesWritten := 0
	readErrors := make(chan error, 1)
	var tcpConn net.Conn
	defer func() {
		// Preserve the failure before closing the connection ourselves.
		if err != nil {
			select {
			case cause := <-readErrors:
				err = cause
			default:
			}
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			err = fmt.Errorf("upload probe wrote %d/%d bytes: %w", bytesWritten, bytesTotal, err)
		}
		if tcpConn != nil {
			tcpConn.Close()
		}
	}()

	// Connect to the proxy and open a tunnel to the site.
	req, err := http.NewRequestWithContext(ctx, "PUT", "https://"+target, nil)
	if err != nil {
		return err
	}
	targetPort := req.URL.Port()
	if targetPort == "" {
		targetPort = "443"
	}
	address := net.JoinHostPort(req.URL.Hostname(), targetPort)
	dialer := net.Dialer{Timeout: time.Duration(cfg.Timeouts.CheckProxy.DialContext) * time.Millisecond}
	tcpConn, err = dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return err
	}
	// Closing the raw connection also interrupts a blocked TLS read or write.
	stop := context.AfterFunc(ctx, func() { tcpConn.Close() })
	defer stop()

	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address,
	}
	if err := connectReq.Write(tcpConn); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tcpConn), connectReq)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy CONNECT returned %s", resp.Status)
	}

	// Establish TLS inside the tunnel.
	tlsConn := tls.Client(tcpConn, &tls.Config{
		RootCAs: certPool, ServerName: req.URL.Hostname(),
		NextProtos: []string{"http/1.1"},
	})
	handshakeCtx := ctx
	if timeout := cfg.Timeouts.CheckProxy.TLSHandshakeTimeout; timeout > 0 {
		var cancel context.CancelFunc
		handshakeCtx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
		defer cancel()
	}
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		return err
	}

	// Recognize a final HTTP response, but keep sending after an early reply.
	responseReady := make(chan struct{})
	go func() {
		reader := bufio.NewReader(tlsConn)
		var err error
		for {
			var resp *http.Response
			resp, err = http.ReadResponse(reader, req)
			if err != nil {
				break
			}
			if resp.StatusCode >= 200 {
				close(responseReady)
				// Read the raw stream so an empty early response does not
				// close the connection while the upload is still running.
				_, err = io.Copy(io.Discard, reader)
				break
			}
			resp.Body.Close()
		}
		if err == nil {
			err = io.EOF
		}
		readErrors <- err
		tcpConn.Close()
	}()

	// Send the HTTP headers without handing body transmission to http.Client.
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", fmt.Sprint(bytesTotal))
	req.Header.Set("Connection", "close")
	var headers strings.Builder
	fmt.Fprintf(&headers, "PUT %s HTTP/1.1\r\nHost: %s\r\n", req.URL.RequestURI(), req.URL.Host)
	req.Header.Write(&headers)
	headers.WriteString("\r\n")
	if _, err := io.WriteString(tlsConn, headers.String()); err != nil {
		return err
	}

	// Write exactly bytesTotal bytes, pausing only between chunks.
	buf := make([]byte, min(bytesPerChunk, bytesTotal))
	for bytesWritten < bytesTotal {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErrors:
			return err
		default:
		}
		chunk := buf[:min(len(buf), bytesTotal-bytesWritten)]
		rand.Read(chunk)
		n, err := tlsConn.Write(chunk)
		bytesWritten += n
		if err != nil {
			return err
		}
		if bytesWritten < bytesTotal && delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-readErrors:
				return err
			case <-time.After(delay):
			}
		}
	}
	// Writes can finish in local/proxy buffers even when the site is stalled.
	// Require an HTTP response too; bound the wait by both configured timeouts.
	var responseTimeout <-chan time.Time
	if timeout := cfg.Timeouts.CheckProxy.ResponseHeaderTimeout; timeout > 0 {
		responseTimeout = time.After(time.Duration(timeout) * time.Millisecond)
	}
	select {
	case <-responseReady:
	case err = <-readErrors:
	case <-ctx.Done():
		err = ctx.Err()
	case <-responseTimeout:
		err = fmt.Errorf("waiting for HTTP response: %w", context.DeadlineExceeded)
	}
	if err == nil {
		select {
		case err = <-readErrors:
		default:
		}
	}
	// A clean close is valid after the full upload and a complete response header.
	if errors.Is(err, io.EOF) {
		select {
		case <-responseReady:
			err = nil
		default:
		}
	}
	return err
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

	if resp.StatusCode >= 400 && resp.StatusCode != 404 && resp.StatusCode != 405 && resp.StatusCode != 418 {
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
		log.Printf("%s Proxy %s return only %d bytes. Too short responce",
			method, proxyURL, n)
		return res
	}

	log.Printf("%s Proxy %s OK %s | bytes=%d | time=%s | ttfb=%s | speed=%.2f KB/s",
		method, proxyURL, target, n, totalTime, ttfb, res.Speed/1024)

	res.OK = true
	return res
}

// Проверка доступности прокси через target
func checkProxy(ctx context.Context, proxyURL *url.URL, target string, method string) CheckResult {
	if method == "PUT" {
		ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Timeouts.CheckProxy.Timeout)*time.Millisecond)
		defer cancel()

		start := time.Now()
		err := dpiUploadProbe(
			ctx,
			proxyURL,
			target,
			cfg.DPI.UploadProbe.TotalSizeBytes,
			cfg.DPI.UploadProbe.ChunkSizeBytes,
			time.Duration(cfg.DPI.UploadProbe.DelayMS)*time.Millisecond,
		)

		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return CheckResult{OK: true}
			}

			if strings.Contains(err.Error(), "use of closed network connection") {
				return CheckResult{OK: true}
			}
			log.Printf("PUT Remove proxy %s from check for %s. Returned error: %s. DPI or site restrictions?", proxyURL, target, err)
			return CheckResult{}
		}

		log.Printf("PUT Proxy %s wrote %d bytes to %s in %s", proxyURL, cfg.DPI.UploadProbe.TotalSizeBytes, target, time.Since(start))
		return CheckResult{OK: true}
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	client := &http.Client{
		Jar: jar,
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

	baseReq, err := http.NewRequestWithContext(ctx, method, "https://"+target, nil)
	if err != nil {
		return CheckResult{}
	}
	baseReq.Header.Set("User-Agent", cfg.UserAgent)
	baseReq.Header.Set("Accept", "*/*")
	baseReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	baseReq.Header.Set("Origin", "https://"+target)
	baseReq.Header.Set("Accept-Encoding", "identity")

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

func waitForRecheckSlot(domain string) {
	limit := cfg.DPI.RecheckLimit
	window := time.Duration(cfg.DPI.RecheckWindowSeconds) * time.Second
	key := mainDomain(domain)

	for {
		now := time.Now()
		cutoff := now.Add(-window)

		recheckMu.Lock()
		starts := rechecks[key]
		firstActive := 0
		for firstActive < len(starts) && !starts[firstActive].After(cutoff) {
			firstActive++
		}
		starts = starts[firstActive:]

		if len(starts) < limit {
			rechecks[key] = append(starts, now)
			recheckMu.Unlock()
			return
		}

		wait := starts[0].Add(window).Sub(now)
		rechecks[key] = starts
		recheckMu.Unlock()

		if wait > 0 {
			time.Sleep(wait)
		}
	}
}

func scheduleRecheckCleanup(domain string) {
	window := time.Duration(cfg.DPI.RecheckWindowSeconds) * time.Second
	key := mainDomain(domain)

	time.AfterFunc(window, func() {
		cutoff := time.Now().Add(-window)

		recheckMu.Lock()
		defer recheckMu.Unlock()

		starts := rechecks[key]
		firstActive := 0
		for firstActive < len(starts) && !starts[firstActive].After(cutoff) {
			firstActive++
		}

		if firstActive == len(starts) {
			delete(rechecks, key)
			return
		}
		rechecks[key] = starts[firstActive:]
	})
}

func runCheckSubdomain(domain string, proxy string, proxies []*Proxy) {
	waitForRecheckSlot(domain)
	defer scheduleRecheckCleanup(domain)

	if res := cacheGet(domain); res.Found && !res.Expired {
		return
	}

	proxies = filterProxies(domain, proxies, true)
	for i, p := range proxies {
		if p.URL == proxy && i != len(proxies)-1 {
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
	resultsHEAD := make([]*ProxyResult, 0, len(proxies))
	results := make([]*ProxyResult, 0, len(proxies))
	resultsGET := make([]*ProxyResult, 0, len(proxies))
	// ctx := context.WithoutCancel(context.Background())
	// if cfg.DPI.UsePUTinRechecks || len(proxies) > 1 {
	// 	log.Printf("Start PUT check for domain %s", domain)
	// 	for _, proxy := range proxies {
	// 		results = append(results, checkProxyAsync(ctx, proxy, domain, "PUT"))
	// 	}
	// 	for _, r := range results {
	// 		<-r.Ready
	// 		if r.OK {
	// 			localProxies = append(localProxies, r.Proxy)
	// 		}
	// 	}
	// } else {
	// localProxies = proxies
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

	log.Printf("Start GET check for domain %s", domain)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, proxy := range proxies {
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

	log.Printf("Start HEAD check for domain %s", domain)
	for _, proxy := range proxies {
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

	uniqueProxies := proxies
	if len(proxies) > 1 {
		checkDomainExeptionsProxiesHEAD := checkDomainExeptions(domain, resultsHEAD, proxies, "HEAD")
		if len(checkDomainExeptionsProxiesHEAD) == 1 {
			cacheSet(domain, checkDomainExeptionsProxiesHEAD[0].URL)
			return
		}
		checkDomainExeptionsProxiesGET := checkDomainExeptions(domain, resultsGET, proxies, "GET")
		if len(checkDomainExeptionsProxiesGET) == 1 {
			cacheSet(domain, checkDomainExeptionsProxiesGET[0].URL)
			return
		}

		// Deduplicate proxy list
		uniqueProxies = make([]*Proxy, 0, len(checkDomainExeptionsProxiesHEAD)+len(checkDomainExeptionsProxiesGET))
		addedProxies := make(map[*Proxy]bool)

		for _, proxy := range append(checkDomainExeptionsProxiesHEAD, checkDomainExeptionsProxiesGET...) {
			if addedProxies[proxy] {
				continue
			}
			addedProxies[proxy] = true
			uniqueProxies = append(uniqueProxies, proxy)
		}

	}
	if cfg.DPI.UsePUTinRechecks || len(proxies) > 1 {
		log.Printf("Start PUT check for domain %s", domain)
		for _, proxy := range uniqueProxies {
			results = append(results, checkProxyAsync(ctx, proxy, domain, "PUT"))
		}
		for _, r := range results {
			<-r.Ready
			if r.OK {
				cancel()
				cacheSet(domain, r.Proxy.URL)
				log.Printf("Selected proxy %s for domain %s via PUT", r.Proxy.URL, domain)
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

func checkDomainExeptions(domain string, results []*ProxyResult, proxies []*Proxy, method string) []*Proxy {
	localProxies := make([]*Proxy, 0, len(proxies))
	for _, v := range results {
		if v.Status != 0 {
			localProxies = append(localProxies, v.Proxy)
		}
	}
	if len(localProxies) == 1 {
		log.Printf("Updated proxy %s for domain %s as its only one working proxy in %s", localProxies[0].URL, domain, method)
		return localProxies
	}

	idx := len(proxies) - 1
	for i := len(proxies) - 1; i > 0; i-- {
		if results[i].Status == results[i-1].Status {
			idx--
			if i != 1 || len(proxies) == len(cfg.Proxies) || (results[i].Status == 403 && i == 1 && len(proxies) > 2) {
				continue
			}
		}
		if idx != len(proxies)-1 {
			log.Printf("Updated proxy %s for domain %s based on %s response difference", proxies[idx].URL, domain, method)
			return proxies[idx : idx+1]
		}
	}
	return localProxies
}
