package resolver

import (
	"log"
	"time"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	upstreamQueryTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "foxdns_resolver_upstream_query_time_seconds",
		Help:    "The time it took to query an upstream resolver",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	}, []string{"server"})

	upstreamQueryErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "foxdns_resolver_upstream_query_errors_total",
		Help: "The total number of errors while querying upstream resolvers",
	}, []string{"server"})
)

func (r *Generator) exchange(m *dns.Msg) (resp *dns.Msg, server string, err error) {
	var info *connInfo
	info, err = r.acquireConn()
	server = info.server.Addr
	if err != nil {
		r.returnConn(info, err)
		return
	}

	startTime := time.Now()
	resp, _, err = info.server.client.ExchangeWithConn(m, info.conn)
	r.returnConn(info, err)

	if err == nil {
		duration := time.Since(startTime)
		upstreamQueryTime.WithLabelValues(info.server.Addr).Observe(duration.Seconds())
	}
	return
}

func (r *Generator) exchangeWithRetry(q *dns.Question) (resp *dns.Msg, err error) {
	m := &dns.Msg{
		Question: []dns.Question{*q},
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
		},
	}

	util.SetEDNS0(m, r.shouldPadLen)

	var server string
	for i := r.Retries; i > 0; i-- {
		resp, server, err = r.exchange(m)
		if err == nil {
			return
		}
		upstreamQueryErrors.WithLabelValues(server).Inc()
		time.Sleep(r.RetryWait)
	}

	if r.LogFailures && (err != nil || resp == nil || resp.Rcode == dns.RcodeServerFailure) {
		rcodeStr := ""
		if resp != nil {
			rcodeStr = dns.RcodeToString[resp.Rcode]
		}
		log.Printf("Failed to resolve %s[%s] @%s: %v (%s)", q.Name, dns.TypeToString[q.Qtype], server, err, rcodeStr)
	}

	return
}
