FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.21-alpine as builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates

ARG GIT_REVISION=dev

ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download

COPY . /src
RUN go build -ldflags="-s -w -X=github.com/Doridian/foxDNS/util.Version=${GIT_REVISION}" -trimpath -o /foxdns ./cmd/foxdns

FROM --platform=${TARGETPLATFORM:-linux/amd64} scratch AS nossl

ENV PUID=1000
ENV PGID=1000

WORKDIR /config
VOLUME /config

COPY --from=builder /foxdns /foxdns

ENTRYPOINT [ "/foxdns" ]

FROM --platform=${TARGETPLATFORM:-linux/amd64} nossl AS default

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
