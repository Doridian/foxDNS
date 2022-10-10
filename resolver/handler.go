package resolver

import (
	"log"

	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

func (r *Resolver) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	reply := new(dns.Msg)
	if len(msg.Question) != 1 {
		wr.WriteMsg(reply.SetRcode(msg, dns.RcodeRefused))
		return
	}

	reply.SetRcode(msg, dns.RcodeServerFailure)
	defer wr.WriteMsg(reply)

	if r.AllowOnlyFromPrivate {
		ip := util.ExtractIP(wr.RemoteAddr())
		if !util.IPIsPrivateOrLocal(ip) {
			reply.RecursionAvailable = false
			reply.Rcode = dns.RcodeRefused
			return
		}
	}

	recursionReply, err := r.Exchange(msg)
	if err != nil {
		log.Printf("Error handling DNS request: %v", err)
		return
	}

	reply.Rcode = recursionReply.Rcode
	reply.Answer = recursionReply.Answer
	reply.Ns = recursionReply.Ns

	if reply.Rcode == dns.RcodeSuccess {
		util.SetEDNS0(reply)
	}
}
