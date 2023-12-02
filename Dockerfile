FROM golang:1.21-alpine AS builder

RUN apk --no-cache add upx

ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download

COPY . /src
RUN go build -o /foxdns ./cmd/foxdns
RUN upx /foxdns -o /foxdns-compressed

FROM scratch AS base

ENV FOXDNS_UID=1000
ENV FOXDNS_GID=1000

WORKDIR /config
VOLUME /config

ENTRYPOINT [ "/foxdns" ]

FROM base AS uncompressed
COPY --from=builder /foxdns /foxdns

FROM base AS compressed
COPY --from=builder /foxdns-compressed /foxdns