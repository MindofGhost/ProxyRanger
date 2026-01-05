# === Build stage ===
FROM golang:1.21 AS builder

WORKDIR /app

# copy source
COPY . .

# SET compiller settings (ARMv7)
ENV GOOS=linux
ENV GOARCH=arm64
ENV CGO_ENABLED=0

# Build binary
RUN go build -ldflags="-s -w -buildid=" -trimpath -o proxy main.go

# === Final stage ===
FROM alpine:latest

# Add custom cerificates support
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/proxy .
RUN chmod +x proxy

COPY proxies.txt /app/
EXPOSE 9990

CMD ["./proxy"]
