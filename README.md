# ProxyRanger
HTTP proxy written in Go that tests user-requested sites through multiple upstream proxies to find the optimal route. Supports automatic routing, DPI-aware probing, intelligent caching, and flexible YAML configuration.

---
## Features

- Tests sites requested by users via GET, HEAD, and optional PUT probing
- Detects DPI-related blocking by validating response size and behavior
- Uses second-level domains for fast routing decisions while caching all subdomains
- Automatically selects the optimal upstream HTTP proxy
- Revalidates cached routes and removes expired cache entries automatically
- Supports user-defined routing overrides
- Flexible YAML-based configuration
- Supports custom CA and self-signed certificates
- Lightweight and high-performance, tested with hundreds of Mbps

---

## Use Cases

ProxyRanger was built to solve real-world routing challenges:

- Sites that only work from specific countries (geo-restrictions)
- DPI bypass tools are breaking some websites
- Networks where different domains require different routes
- Complex routing where static rules are insufficient

---

## How It Works

1. User(or clash/singbox/browser/etc..) sends an HTTP/HTTPS request to ProxyRanger
2. Upstream proxies are filtered and prioritized using optional regex-based whitelist and blacklist rules
3. ProxyRanger tests the requested site(SNI) through multiple upstream proxies using GET and HEAD requests
4. If the response appears suspiciously short or incomplete, ProxyRanger can additionally use PUT upload probing to detect DPI interference
5. The first upstream that successfully passes validation is selected
6. Cached entries are periodically revalidated and cleaned up automatically
7. User overrides can be applied for domains that require special routing

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

### 3. Configure ProxyRanger

Create or edit `config.yml`.
ProxyRanger uses a default internal configuration (default.yml) which is merged with the user-provided config automatically.

Example minimal config.yml:
```
proxies:
  - url: http://127.0.0.1:8880
  - url: http://127.0.0.1:8888
  - url: http://127.0.0.1:9994
```

#### 3.1. Configure upstream proxies

The `proxies` section is mandatory and must be filled by the user.

Recommended priority order:

1. Direct connection
2. DPI bypass tools
3. Foreign endpoints
4. Fallback proxy

Optional regex-based routing and prioritization rules are supported:

```yaml
proxies:
  - url: http://127.0.0.1:9994
    whitelist:
      - ".*youtube.*"
      - ".*googlevideo.*"

  - url: http://127.0.0.1:9995
    blacklist:
      - ".*bank.*"
```

##### Proxy filtering and prioritization

Each upstream proxy can define optional `whitelist` and `blacklist` rules using regular expressions.

Behavior:

- `whitelist` — ProxyRanger will prioritize this proxy for matching domains
- `blacklist` — ProxyRanger will skip this proxy for matching domains

This allows flexible geo-routing and DPI-aware routing policies.

Example behavior:

- traffic for YouTube-related domains will prefer proxy `9994`
- banking domains will never be tested through proxy `9995`

> Authentication and HTTPS proxies are not supported directly.
>
> Recommended approach: use local HTTP proxies on `127.0.0.1` that forward traffic over secure protocols (sing-box, gost, Shadowsocks, etc...)

### 4. Configure user overrides (optional)

To override routing for specific domains, create ./cache/user.json:
```
{
  "site1.com": "http://127.0.0.1:9994",
  "example.net": "http://127.0.0.1:9993"
}
```
> These rules will merge with ProxyRanger's automatic routing logic. This rules will never expire.

### 5. Add custom certificates (optional)

If you need to test sites with self-signed or custom CA certificates, place them in the certs (default: `./certs`) directory.
ProxyRanger will use these certificates for domain accessibility checks.

### 6. Build and run via Docker Compose

Edit the Dockerfile and adjust the GOARCH environment variable. Most users will use `amd64`. On ARM devices like OrangePi, set it to `arm64`.

```
docker compose up --build -d
```

By default, ProxyRanger listens on all interfaces at port `9990`.

#### Check container logs:

```
docker compose logs -f proxyranger
```

### 7. Verify operation

- Send HTTP requests through ProxyRanger to any domain.
- The proxy will automatically select the first working upstream and cache the result. The cache is saved to a file every 5 minutes (you can cahge save period in config).
- Cached entries are revalidated automatically according to configured TTL value
- Old cache entries are cleaned up automatically according to configured max age value

## Automatic cache maintenance

The cache system supports:

- Automatic revalidation
- TTL-based refresh
- Expiration cleanup
- Periodic persistence to disk

Configuration:

```yaml
cache:
  ttl: 2h
  maxAge: 240h
  saveTime: 5m
  cleanupInterval: 12h
```

Meaning:

- `ttl` — how long a cached route is trusted before revalidation
- `maxAge` — how long will a cache entry be stored before being deleted after its last use
- `saveTime` — interval for saving cache to disk
- `cleanupInterval` — interval for removing expired entries

## DPI Detection Logic

Some DPI systems allow connections but silently corrupt or truncate responses.

To detect this behavior, ProxyRanger:

- Performs `GET` and `HEAD` requests
- Validates response size
- Optionally performs upload probing using `PUT`
- Retries GET/HEAD checks if necessary

Configuration:

```yaml
dpi:
  uploadProbe:
    totalSizeBytes: 3840
    chunkSizeBytes: 160
    delayMS: 30

  retryAttempts: 1
  usePUTinRechecks: false
  recheckLimit: 1
  recheckWindowSeconds: 60
```

Meaning:

- `totalSizeBytes` — total upload size used for DPI probing
- `chunkSizeBytes` — upload chunk size
- `delayMS` — delay between chunks
- `retryAttempts` — number of repeated validation attempts
- `usePUTinRechecks` — whether PUT probing is used during cache revalidation

> Rate-limit settings to help avoid website anti-DDoS protection:
- `recheckLimit` — maximum total rechecks for a main domain and all its subdomains during a rate-limit window
- `recheckWindowSeconds` — recheck rate-limit window in seconds


## Current limitations

- Some DPI systems may still require manual override rules
- Authentication and full HTTPS proxies are not supported directly; use local HTTP proxy forwards (e.g., sing-box, gost)

## Roadmap (planned improvements)

- Runtime configuration reload
- Configurable probing strategies
