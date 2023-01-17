FROM golang:1.19-alpine AS builder

ENV CGO_ENABLED=0

WORKDIR /src

COPY go.mod go.sum /src/
RUN go mod download

COPY . /src
RUN go build  -o /foxdns ./cmd/foxdns

FROM scratch

ENV FOXDNS_UID=1000
ENV FOXDNS_GID=1000

WORKDIR /config
VOLUME /config

COPY --from=builder /foxdns /foxdns

ENTRYPOINT [ "/foxdns" ]
