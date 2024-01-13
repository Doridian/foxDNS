package resolver

import (
	"log"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (r *Generator) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	util.SetHandlerName(wr, r)

	reply := &dns.Msg{
		Compress: true,
	}
	if len(msg.Question) != 1 {
		_ = wr.WriteMsg(reply.SetRcode(msg, dns.RcodeRefused))
		return
	}
	reply.SetRcode(msg, dns.RcodeServerFailure)

	ok, option := util.ApplyEDNS0ReplyEarly(msg, reply, wr, r.RequireCookie)
	if !ok {
		_ = wr.WriteMsg(reply)
		return
	}

	var recursionReplyEdns0 *dns.OPT

	defer func() {
		replyEdns0 := util.ApplyEDNS0Reply(msg, reply, option, wr, r.RequireCookie)
		if replyEdns0 != nil && recursionReplyEdns0 != nil && recursionReplyEdns0.Version() == 0 {
			replyEdns0.SetDo(recursionReplyEdns0.Do())
		}

		if replyEdns0 == nil && reply.Rcode > 0xF {
			// Unset extended RCODE if client doesn't speak EDNS0
			reply.Rcode = dns.RcodeServerFailure
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

	recursionReply, err := r.getOrAddCache(q)
	if err != nil {
		log.Printf("Error handling DNS request: %v", err)
		return
	}

	reply.Rcode = recursionReply.Rcode
	reply.Answer = recursionReply.Answer
	reply.Ns = recursionReply.Ns
	recursionReplyEdns0 = recursionReply.IsEdns0()
}
