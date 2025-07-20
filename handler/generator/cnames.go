package generator

import (
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (h *Handler) resolveIfCNAME(reply *dns.Msg, questions []dns.Question, wr util.Addressable) {
	qtype := questions[0].Qtype
	// There can only legally ever be 1 CNAME, so dont even bother checking is multiple records
	if reply.Rcode != dns.RcodeSuccess || qtype == dns.TypeCNAME || len(reply.Answer) != 1 {
		return
	}

	cname, ok := reply.Answer[0].(*dns.CNAME)
	if !ok {
		return
	}

	h.subQuery(reply, questions, dns.Question{
		Name:   dns.CanonicalName(cname.Target),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}, wr)
}
