package generator

import (
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (h *Handler) resolveIfCNAME(reply *dns.Msg, msg *dns.Msg, q *dns.Question, wr util.Addressable, queryDepth int) {
	// There can only legally ever be 1 CNAME, so dont even bother checking is multiple records
	if reply.Rcode != dns.RcodeSuccess || q.Qtype == dns.TypeCNAME || len(reply.Answer) != 1 {
		return
	}

	cname, ok := reply.Answer[0].(*dns.CNAME)
	if !ok {
		return
	}

	for auxQs := range msg.Question {
		if msg.Question[auxQs].Name == cname.Target {
			return // Already queried this CNAME
		}
	}

	resp := &RecursiveResponseWriter{
		wr: wr,
	}

	cnameQ := &dns.Msg{}
	cnameQ.SetQuestion(cname.Target, q.Qtype)
	cnameQ.Question = append(cnameQ.Question, msg.Question...)

	h.mux.ServeDNS(resp, cnameQ)

	if resp.reply != nil && resp.reply.Rcode == dns.RcodeSuccess {
		reply.Answer = append(reply.Answer, resp.reply.Answer...)
	}
}
