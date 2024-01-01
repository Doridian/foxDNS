package resolver

import (
	"log"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (r *Generator) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	util.SetHandlerName(wr, r)

	reply := &dns.Msg{}
	if len(msg.Question) != 1 {
		_ = wr.WriteMsg(reply.SetRcode(msg, dns.RcodeRefused))
		return
	}

	reply.SetRcode(msg, dns.RcodeServerFailure)
	defer func() {
		replyEdns0, queryEdns0 := util.ApplyEDNS0ReplyIfNeeded(msg, reply, wr)
		if replyEdns0 != nil && queryEdns0 != nil && queryEdns0.Version() == 0 {
			replyEdns0.SetDo(queryEdns0.Do())
			replyEdns0.SetExtendedRcode(uint16(queryEdns0.ExtendedRcode()))
		}

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

	reply.Rcode = recursionReply.Rcode
	reply.Answer = recursionReply.Answer
	reply.Ns = recursionReply.Ns
}
