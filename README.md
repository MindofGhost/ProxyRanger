# ProxyRanger
HTTP proxy written in Go that tests user-requested sites through multiple upstream proxies to find the optimal route. Caches working upstreams for each second-level domain and supports user overrides for complex geo and DPI-aware routing scenarios.

---
## Features

- Tests sites requested by users via GET and HEAD requests
- Also evaluates second-level domains to ensure full site accessibility
- Automatically selects the optimal upstream HTTP proxy
- Caches working upstreams for each second-level domain for fast startup and operation
- Supports user-defined overrides for sites that require custom routing
- Lightweight and high-performance, tested with hundreds of Mbps

---

## Use Cases

ProxyRanger was built to solve real-world routing challenges:

- Sites that only work from specific countries (geo-restrictions)
- DPI bypass tools are breaking some websites
- Complex routing where static rules are insufficient

---

## How It Works

1. User(or clash/singbox/etc..) sends an HTTP/HTTPS request to ProxyRanger
2. ProxyRanger tests the requested site(SNI) through multiple upstream proxies using GET and HEAD requests
3. The first upstream that responds correctly for the second-level domain is selected  
4. The working upstream is cached for future requests  
5. User overrides can be applied for domains that require special routing  

---

## Quick Start (Docker)

Follow these steps to run **ProxyRanger** using Docker.

---

### 1. Install Docker

Ensure Docker and Docker Compose are installed
(For installation instructions, see [Docker](https://docs.docker.com/engine/install/)):

```bash
docker --version
docker compose version
```

### 2. Clone the repository
```
git clone https://github.com/MindofGhost/ProxyRanger.git
cd ProxyRanger
```

### 3. Configure upstream proxies

Edit proxies.txt and list your upstream proxies in descending order of priority:
- First: direct connection (highest priority)
- Next: DPI-bypass tools
- Then: endpoints in other countries
- Last: fallback server (also used if all checks fail; in this case will not be cached)

> Authentication and HTTPS proxies are not supported directly.
> Recommended: use local HTTP proxies on 127.0.0.1 that forward traffic over secure protocols (e.g., sing-box, gost, etc.).

Example proxies.txt:
```
http://127.0.0.1:9991
http://127.0.0.1:9992
http://127.0.0.1:9993
http://127.0.0.1:9994
```

### 4. Configure user overrides (optional)

To override routing for specific domains, create ./cache/user.json:
```
{
  "site1.com": "http://127.0.0.1:9994",
  "example.net": "http://127.0.0.1:9993"
}
```
> These rules will merge with ProxyRanger's automatic routing logic.

### 5. Add custom certificates (optional)

If you need to test sites with self-signed or custom CA certificates, place them in the ./certs directory.
ProxyRanger will use these certificates for domain accessibility checks.

### 6. Build and run via Docker Compose
```
docker compose up --build -d
```

<mark>By default, ProxyRanger listens on all interfaces at port 9990.</mark>

<mark>Port override is currently not supported; restrict access via iptables or edit the code manually if needed.</mark>

#### Check container logs:

```
docker compose logs -f proxyranger
```

### 7. Verify operation

- Send HTTP requests through ProxyRanger to any domain.
- The proxy will automatically select the first working upstream and cache the result. The cache is saved to a file every 5 minutes. 
- To reset the cache, delete ./cache/cache.json and restart the container.

## Current limitations

- Cached upstreams do not expire automatically. To refresh, manually delete ./cache/cache.json or set up a periodic cleanup using cron and restart ProxyRanger.
- Listening port is fixed and cannot be changed without modifying the code
- Authentication and full HTTPS proxies are not supported directly; use local HTTP proxy forwards (e.g., sing-box, gost)

## Roadmap (planned improvements)

- Automatic re-check of cached upstreams on failure
- Configurable listening port and interfaces
  
