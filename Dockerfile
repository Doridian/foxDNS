FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.25-alpine as builder

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
RUN go build -ldflags="-s -w -X=github.com/Doridian/foxDNS/util.Version=${GIT_REVISION}" -trimpath -o /foxDNS ./cmd/foxDNS

FROM alpine AS compressor
RUN apk add --no-cache upx
COPY --from=builder /foxDNS /foxDNS
RUN upx -9 /foxDNS -o /foxDNS-compressed

FROM --platform=${TARGETPLATFORM:-linux/amd64} scratch AS nossl-base

ENV PUID=1000
ENV PGID=1000

WORKDIR /config
VOLUME /config

ENTRYPOINT [ "/foxDNS" ]

FROM --platform=${TARGETPLATFORM:-linux/amd64} nossl-base AS nossl
COPY --from=builder /foxDNS /foxDNS

FROM --platform=${TARGETPLATFORM:-linux/amd64} nossl-base AS nossl-compressed
COPY --from=compressor /foxDNS-compressed /foxDNS

FROM --platform=${TARGETPLATFORM:-linux/amd64} nossl AS default
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

FROM --platform=${TARGETPLATFORM:-linux/amd64} nossl-compressed AS compressed
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
