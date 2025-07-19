package handler

import (
	"crypto"
	"sync"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	queriesProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "foxdns_queries_processed_total",
		Help: "The total number of processed DNS queries",
	}, []string{"qtype", "rcode", "handler", "extended_rcode"})

	queryProcessingTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "foxdns_query_processing_time_seconds",
		Help:    "The time it took to process a DNS query",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	}, []string{"handler"})
)

type Handler struct {
	child generator.Generator
	mux   *dns.ServeMux

	RequireCookie bool
	soa           []dns.RR
	ns            []dns.RR
	zone          string

	authoritative bool

	enableSignatureCache bool
	signatureLock        sync.Mutex
	signatures           map[string]*dns.RRSIG
	signerName           string
	zskDNSKEY            *dns.DNSKEY
	zskPrivateKey        crypto.PrivateKey
	kskDNSKEY            *dns.DNSKEY
	kskPrivateKey        crypto.PrivateKey

	recursionAvailable bool
}

func New(mux *dns.ServeMux, child generator.Generator, zone string, config Config) *Handler {
	hdl := &Handler{
		child: child,
		zone:  dns.CanonicalName(zone),
		mux:   mux,
	}
	hdl.loadConfig(config)
	return hdl
}

func (h *Handler) clearCache() {
	h.signatureLock.Lock()
	h.signatures = make(map[string]*dns.RRSIG)
	h.signatureLock.Unlock()
}

func (h *Handler) Refresh() error {
	h.clearCache()
	return nil
}

func (h *Handler) Start() error {
	h.clearCache()
	return nil
}

func (h *Handler) Stop() error {
	h.clearCache()
	return nil
}

func FillAuthHeader(rr dns.RR, rtype uint16, zone string, ttl uint32) dns.RR {
	return util.FillHeader(rr, zone, rtype, ttl)
}
