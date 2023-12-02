FROM golang:1.21-alpine AS builder

RUN apk --no-cache add upx

ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download

COPY . /src
RUN go build -ldflags='-s -w' -trimpath -o /foxdns ./cmd/foxdns
RUN upx -9 /foxdns -o /foxdns-compressed

FROM scratch AS base

ENV PUID=1000
ENV PGID=1000

WORKDIR /config
VOLUME /config

ENTRYPOINT [ "/foxdns" ]

FROM base AS uncompressed
COPY --from=builder /foxdns /foxdns

FROM base AS compressed
COPY --from=builder /foxdns-compressed /foxdns