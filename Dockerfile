FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.23-alpine as builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates upx

ARG GIT_REVISION=dev

ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download

COPY . /src
RUN go build -ldflags="-s -w -X=github.com/Doridian/foxDNS/util.Version=${GIT_REVISION}" -trimpath -o /foxdns ./cmd/foxdns

FROM alpine AS compressor
RUN apk add --no-cache upx
COPY --from=builder /foxdns /foxdns
RUN upx -9 /foxdns -o /foxdns-compressed

FROM --platform=${TARGETPLATFORM:-linux/amd64} scratch AS nossl-base

ENV PUID=1000
ENV PGID=1000

WORKDIR /config
VOLUME /config

ENTRYPOINT [ "/foxdns" ]

FROM --platform=${TARGETPLATFORM:-linux/amd64} nossl-base AS nossl
COPY --from=builder /foxdns /foxdns

FROM --platform=${TARGETPLATFORM:-linux/amd64} nossl-base AS nossl-compressed
COPY --from=compressor /foxdns-compressed /foxdns

FROM --platform=${TARGETPLATFORM:-linux/amd64} nossl AS default
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

FROM --platform=${TARGETPLATFORM:-linux/amd64} nossl-compressed AS compressed
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
