package resolver

import (
	"encoding/hex"
	"errors"
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
	startTime := r.CurrentTime()
	resp, _, err = info.server.client.ExchangeWithConn(m, info.conn)

	if err == nil {
		duration := time.Since(startTime)
		upstreamQueryTime.WithLabelValues(info.server.Addr).Observe(duration.Seconds())
	}
	return
}

var ErrCookieMismatch = errors.New("client cookie returned from server invalid")

func (r *Generator) exchangeWithRetry(q *dns.Question) (resp *dns.Msg, err error) {
	var info *connInfo
	var keepConn bool = false

	for currentTry := 1; currentTry <= r.Attempts; currentTry++ {
		if info != nil && !keepConn {
			r.returnConn(info, err)
			upstreamQueryErrors.WithLabelValues(info.server.Addr).Inc()
			info = nil
			err = nil
			time.Sleep(r.RetryWait)
		}

		keepConn = false
		if info == nil {
			info, err = r.acquireConn(currentTry)
		}

		if err != nil {
			continue
		}

		m := &dns.Msg{
			Compress: true,
			Question: []dns.Question{*q},
			MsgHdr: dns.MsgHdr{
				Opcode:           dns.OpcodeQuery,
				RecursionDesired: true,
			},
		}

		// We never need the previous cookie here as we just compare generated vs returned
		clientCookie := util.GenerateClientCookie(false, info.server.Addr)
		if clientCookie == nil {
			err = errors.New("failed to generate client cookie")
			continue
		}

		edns0Opts := make([]dns.EDNS0, 0, 1)
		if info.server.RequireCookie || !util.IsSecureProtocol(info.conn.RemoteAddr().Network()) {
			edns0Opts = append(edns0Opts, &dns.EDNS0_COOKIE{
				Code:   dns.EDNS0COOKIE,
				Cookie: hex.EncodeToString(append(clientCookie, info.serverCookie...)),
			})
		}
		util.SetEDNS0(m, edns0Opts, r.shouldPadLen)

		resp, err = r.exchange(info, m)
		if err != nil {
			continue
		}

		cookieMatch := false
		if serverEDNS0 := resp.IsEdns0(); serverEDNS0 != nil && serverEDNS0.Version() == 0 {
			for _, opt := range serverEDNS0.Option {
				if opt.Option() != dns.EDNS0COOKIE {
					continue
				}
				cookieOpt, ok := opt.(*dns.EDNS0_COOKIE)
				if !ok {
					continue
				}

				binaryCookie, err := hex.DecodeString(cookieOpt.Cookie)
				if err != nil || binaryCookie == nil {
					continue
				}

				if len(binaryCookie) < util.ClientCookieLength+util.MinServerCookieLength {
					continue
				}

				if util.CookieCompare(binaryCookie[:util.ClientCookieLength], clientCookie) {
					info.serverCookie = binaryCookie[util.ClientCookieLength:]
					cookieMatch = true
				}
			}
		}

		if !cookieMatch && info.server.RequireCookie {
			err = ErrCookieMismatch
			continue
		}

		if resp.Rcode == dns.RcodeBadCookie {
			keepConn = true
			currentTry--
			continue
		}

		r.returnConn(info, nil)
		return
	}

	r.returnConn(info, err)

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
