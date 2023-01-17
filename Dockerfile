FROM golang:1.19-alpine AS builder

ENV CGO_ENABLED=0
COPY . /src
WORKDIR /src
RUN go build  -o /foxdns ./cmd/foxdns

FROM scratch

ENV FOXDNS_UID=1000
ENV FOXDNS_GID=1000

WORKDIR /
VOLUME /config

COPY --from=builder /foxdns /foxdns

ENTRYPOINT [ "/foxdns" ]
CMD [ "/config/config.yml" ]
