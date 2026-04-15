package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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

		log.Printf("CONNECT %s via %s", target, upstream)

		upURL, err := url.Parse(upstream)
		if err != nil {
			log.Printf("Invalid upstream URL: %v", err)
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			clientConn.Close()
			return
		}

		// Dial с keepalive
		dialer := net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		upstreamConn, err := dialer.Dial("tcp", upURL.Host)
		if err != nil {
			log.Printf("Dial upstream error: %v", err)
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			clientConn.Close()
			return
		}

		// Включаем TCP keepalive
		if tcp, ok := upstreamConn.(*net.TCPConn); ok {
			tcp.SetKeepAlive(true)
			tcp.SetKeepAlivePeriod(30 * time.Second)
		}
		if tcp, ok := clientConn.(*net.TCPConn); ok {
			tcp.SetKeepAlive(true)
			tcp.SetKeepAlivePeriod(30 * time.Second)
		}

		// Отправляем CONNECT на upstream
		connectReq := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
		if _, err := upstreamConn.Write([]byte(connectReq)); err != nil {
			log.Printf("Upstream write error: %v", err)
			clientConn.Close()
			upstreamConn.Close()
			return
		}

		// Читаем ответ от upstream
		reader := bufio.NewReader(upstreamConn)
		resp, err := http.ReadResponse(reader, r)
		if err != nil {
			log.Printf("Upstream CONNECT read error: %v", err)
			clientConn.Close()
			upstreamConn.Close()
			return
		}
		resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Printf("Upstream %s refused CONNECT (%d) to %s", upstream, resp.StatusCode, r.Host)
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			clientConn.Close()
			upstreamConn.Close()
			return
		}

		// Подтверждаем клиенту
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			upstreamConn.Close()
			clientConn.Close()
			return
		}

		log.Printf("Tunnel established: %s <-> %s", clientConn.RemoteAddr(), target)

		// Двунаправленное копирование с корректным закрытием
		done := make(chan struct{}, 2)

		go func() {
			_, _ = io.Copy(upstreamConn, clientConn)
			if tcp, ok := upstreamConn.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
			done <- struct{}{}
		}()

		go func() {
			_, _ = io.Copy(clientConn, upstreamConn)
			if tcp, ok := clientConn.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
			done <- struct{}{}
		}()

		// Ждём завершения обеих сторон
		<-done
		<-done

		upstreamConn.Close()
		clientConn.Close()

		log.Printf("Tunnel closed: %s", target)
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
