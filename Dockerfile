FROM golang:1.21-alpine AS builder

WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download

COPY . /src
RUN go build -ldflags='-s -w' -trimpath -o /foxdns ./cmd/foxdns

FROM alpine:3.19 AS default

RUN apk add --no-cache ca-certificates

ENV PUID=1000
ENV PGID=1000

WORKDIR /config
VOLUME /config

COPY --from=builder /foxdns /foxdns

ENTRYPOINT [ "/foxdns" ]
