package resolver

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

func (r *Generator) HandleQuestion(q *dns.Question, remoteIP net.IP) (recs []dns.RR, ns []dns.RR, edns0Opts []dns.EDNS0, rcode int) {
	cacheResult, matchType, upstreamReply, err := r.getOrAddCache(q, false, 1)
	if err != nil {
		rcode = dns.RcodeServerFailure
		log.Printf("Error handling DNS request: %v", err)
		return
	}
	cacheResults.WithLabelValues(cacheResult, matchType).Inc()

	recs = upstreamReply.Answer
	rcode = upstreamReply.Rcode
	ns = upstreamReply.Ns

	upstreamReplyEdns0 := upstreamReply.IsEdns0()
	for _, upstreamOpt := range upstreamReplyEdns0.Option {
		if upstreamOpt.Option() != dns.EDNS0EDE {
			continue
		}

		edns0Opts = []dns.EDNS0{upstreamOpt}
		break
	}

	return
}
