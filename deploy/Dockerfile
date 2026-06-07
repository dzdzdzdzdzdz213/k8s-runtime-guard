FROM golang:1.22 AS builder
WORKDIR /build
COPY loader/go.mod loader/go.sum ./
RUN go mod download
COPY loader/*.go ./
RUN CGO_ENABLED=0 go build -o k8s-runtime-guard .

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libbpf0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/k8s-runtime-guard /usr/local/bin/
COPY config.json /etc/k8s-runtime-guard/config.json
EXPOSE 9090
VOLUME ["/etc/k8s-runtime-guard"]
ENTRYPOINT ["/usr/local/bin/k8s-runtime-guard"]
