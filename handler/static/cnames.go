package static

import (
	"github.com/Doridian/foxDNS/handler"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (r *Generator) resolveIfCNAME(questions []dns.Question, rcode int, recs []dns.RR, wr util.Addressable) {
	qtype := questions[0].Qtype
	// There can only legally ever be 1 CNAME, so dont even bother checking is multiple records
	if rcode != dns.RcodeSuccess || qtype == dns.TypeCNAME || len(recs) != 1 {
		return
	}

	cname, ok := recs[0].(*dns.CNAME)
	if !ok {
		return
	}

	subQ := dns.Question{
		Name:   dns.CanonicalName(cname.Target),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}

	for _, oldQ := range questions {
		if oldQ.Name == subQ.Name && oldQ.Qtype == subQ.Qtype && oldQ.Qclass == subQ.Qclass {
			return // Already queried this one
		}
	}

	resp := handler.NewRecursiveResponseWriter(wr)

	subQMsg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1, len(questions)+1),
	}
	subQMsg.Question[0] = subQ
	subQMsg.Question = append(subQMsg.Question, questions...)

	r.mux.ServeDNS(resp, subQMsg)

	subReply := resp.GetMsg()

	if subReply != nil && subReply.Rcode == dns.RcodeSuccess {
		recs = append(recs, subReply.Answer...)
	}
}
