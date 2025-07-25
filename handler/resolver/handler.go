package resolver

import (
	"log"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (g *Generator) HandleQuestion(questions []dns.Question, recurse bool, dnssec bool, _ util.Addressable) (answer []dns.RR, ns []dns.RR, edns0 []dns.EDNS0, rcode int, handlerName string) {
	rcode = dns.RcodeServerFailure

	cacheResult, matchType, upstreamReply, err := g.getOrAddCache(&questions[0], recurse, false, 1)
	if err != nil {
		log.Printf("Error handling DNS request: %v", err)
		return
	}

	if cacheResult != "" {
		cacheResults.WithLabelValues(cacheResult, matchType).Inc()
	}

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

	if !dnssec {
		newAnswers := make([]dns.RR, 0, len(answer))
		for _, rr := range answer {
			rrType := rr.Header().Rrtype
			if rrType == dns.TypeRRSIG || rrType == dns.TypeNSEC || rrType == dns.TypeNSEC3 {
				continue
			}
			newAnswers = append(newAnswers, rr)
		}
		answer = newAnswers
	}

	return
}
