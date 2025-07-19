package handler

import (
	"time"

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

func MeasureQuery(startTime time.Time, reply *dns.Msg, handlerName string) {
	if len(reply.Question) == 0 {
		return
	}

	duration := time.Since(startTime)

	q := &reply.Question[0]

	rcode := dns.RcodeToString[reply.Rcode]
	if reply.Rcode == dns.RcodeSuccess && len(reply.Answer) == 0 {
		rcode = "NXRECORD"
	}

	extendedRCode := ""
	replyEdns0 := reply.IsEdns0()
	if replyEdns0 != nil {
		for _, opt := range replyEdns0.Option {
			if opt.Option() != dns.EDNS0EDE {
				continue
			}

			edeOpt, ok := opt.(*dns.EDNS0_EDE)
			if !ok {
				continue
			}
			extendedRCode = dns.ExtendedErrorCodeToString[edeOpt.InfoCode]
			break
		}
	}

	queriesProcessed.WithLabelValues(dns.TypeToString[q.Qtype], rcode, handlerName, extendedRCode).Inc()
	queryProcessingTime.WithLabelValues(handlerName).Observe(duration.Seconds())
}
