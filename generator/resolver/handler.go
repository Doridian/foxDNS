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

	recursionReply, downstreamEdns0, err := r.getOrAddCache(q, false)
	if err != nil {
		log.Printf("Error handling DNS request: %v", err)
		return
	}

	reply.Rcode = recursionReply.Rcode
	reply.Answer = recursionReply.Answer
	reply.Ns = recursionReply.Ns

	if msg.IsEdns0() != nil {
		reply.Extra = []dns.RR{downstreamEdns0}
	} else {
		reply.Extra = []dns.RR{}
	}
}
