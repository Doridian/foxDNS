package resolver

import (
	"log"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (r *Generator) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	util.SetHandlerName(wr, r)

	reply := new(dns.Msg)
	if len(msg.Question) != 1 {
		_ = wr.WriteMsg(reply.SetRcode(msg, dns.RcodeRefused))
		return
	}

	reply.SetRcode(msg, dns.RcodeServerFailure)
	defer func() {
		_ = wr.WriteMsg(reply)
	}()

	if r.AllowOnlyFromPrivate {
		ip := util.ExtractIP(wr.RemoteAddr())
		if !util.IPIsPrivateOrLocal(ip) {
			reply.RecursionAvailable = false
			reply.Rcode = dns.RcodeRefused
			return
		}
	}

	reply.RecursionAvailable = true

	q := &msg.Question[0]
	if util.IsBadQuery(q) {
		reply.Rcode = dns.RcodeRefused
		return
	}
	q.Name = dns.CanonicalName(q.Name)

	recursionReply, err := r.getOrAddCache(q, false)
	if err != nil {
		log.Printf("Error handling DNS request: %v", err)
		return
	}

	filteredAnswer := make([]dns.RR, 0, len(recursionReply.Answer))
	for _, rr := range recursionReply.Answer {
		rrType := rr.Header().Rrtype
		if q.Qtype == dns.TypeANY || rrType == q.Qtype || rrType == dns.TypeCNAME {
			filteredAnswer = append(filteredAnswer, rr)
		}
	}
	reply.Rcode = recursionReply.Rcode
	reply.Answer = filteredAnswer
	reply.Ns = recursionReply.Ns

	if reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError {
		util.SetEDNS0(reply)
	}
}
