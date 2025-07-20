package resolver

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

func (g *Generator) HandleQuestion(q *dns.Question, recurse bool, _ net.IP) (answer []dns.RR, ns []dns.RR, edns0 []dns.EDNS0, rcode int) {
	rcode = dns.RcodeServerFailure

	cacheResult, matchType, upstreamReply, err := g.getOrAddCache(q, false, 1)
	if err != nil {
		log.Printf("Error handling DNS request: %v", err)
		return
	}
	cacheResults.WithLabelValues(cacheResult, matchType).Inc()

	rcode = upstreamReply.Rcode
	ns = upstreamReply.Ns
	answer = upstreamReply.Answer
	upstreamReplyEdns0 := upstreamReply.IsEdns0()
	if upstreamReplyEdns0 != nil {
		for _, upstreamOpt := range upstreamReplyEdns0.Option {
			if upstreamOpt.Option() != dns.EDNS0EDE {
				continue
			}

			edns0 = []dns.EDNS0{upstreamOpt}
			break
		}
	}
	return
}
