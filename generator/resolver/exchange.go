package resolver

import (
	"encoding/hex"
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

func (r *Generator) exchange(info *connInfo, m *dns.Msg) (resp *dns.Msg, err error) {
	startTime := time.Now()
	resp, _, err = info.server.client.ExchangeWithConn(m, info.conn)

	if err == nil {
		duration := time.Since(startTime)
		upstreamQueryTime.WithLabelValues(info.server.Addr).Observe(duration.Seconds())
	}
	return
}

func (r *Generator) exchangeWithRetry(q *dns.Question) (resp *dns.Msg, err error) {
	var info *connInfo
	for i := r.Retries; i > 0; i-- {
		info, err = r.acquireConn()
		if err == nil {
			m := &dns.Msg{
				Compress: true,
				Question: []dns.Question{*q},
				MsgHdr: dns.MsgHdr{
					Opcode:           dns.OpcodeQuery,
					RecursionDesired: true,
				},
			}

			edns0Opts := make([]dns.EDNS0, 0, 1)
			if !util.IsSecureProtocol(info.conn.RemoteAddr().Network()) {
				edns0Opts = append(edns0Opts, &dns.EDNS0_COOKIE{
					Code:   dns.EDNS0COOKIE,
					Cookie: hex.EncodeToString(util.GenerateClientCookie(info.server.Addr)) + info.serverCookie,
				})
			}
			util.SetEDNS0(m, edns0Opts, r.shouldPadLen)

			resp, err = r.exchange(info, m)
			r.returnConn(info, err)
			if err == nil {
				if serverEDNS0 := resp.IsEdns0(); serverEDNS0 != nil {
					for _, opt := range serverEDNS0.Option {
						if opt.Option() != dns.EDNS0COOKIE {
							continue
						}
						cookie, ok := opt.(*dns.EDNS0_COOKIE)
						if !ok {
							continue
						}
						if len(cookie.Cookie) < 32 {
							continue
						}
						info.serverCookie = cookie.Cookie[16:] // hex encoded
					}
				}
				return
			}
		} else {
			r.returnConn(info, err)
		}
		upstreamQueryErrors.WithLabelValues(info.server.Addr).Inc()
		time.Sleep(r.RetryWait)
	}

	if r.LogFailures && (err != nil || resp == nil || resp.Rcode == dns.RcodeServerFailure) {
		rcodeStr := ""
		if resp != nil {
			rcodeStr = dns.RcodeToString[resp.Rcode]
		}
		serverAddr := ""
		if info != nil && info.server != nil {
			serverAddr = info.server.Addr
		}
		log.Printf("Failed to resolve %s[%s] @%s: %v (%s)", q.Name, dns.TypeToString[q.Qtype], serverAddr, err, rcodeStr)
	}

	return
}
