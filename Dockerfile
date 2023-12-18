FROM golang:1.21-alpine AS builder

RUN apk add --no-cache ca-certificates

ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download

COPY . /src
RUN go build -ldflags='-s -w' -trimpath -o /foxdns ./cmd/foxdns

FROM scratch AS nossl

ENV PUID=1000
ENV PGID=1000

WORKDIR /config
VOLUME /config

COPY --from=builder /foxdns /foxdns

ENTRYPOINT [ "/foxdns" ]

FROM nossl AS default

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
