package handler

import (
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

type Generator interface {
	GetName() string
	HandleQuestion(questions []dns.Question, recurse bool, dnssec bool, wr util.Addressable) (answer []dns.RR, ns []dns.RR, edns0Opts []dns.EDNS0, rcode int, handlerName string)

	Loadable
}

type Loadable interface {
	Refresh() error
	Start() error
	Stop() error
}
