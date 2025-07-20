package generator

import (
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (h *Handler) resolveIfCNAME(reply *dns.Msg, q *dns.Question, wr util.Addressable, queryDepth uint64) {
	// There can only legally ever be 1 CNAME, so dont even bother checking is multiple records
	if reply.Rcode != dns.RcodeSuccess || q.Qtype == dns.TypeCNAME || len(reply.Answer) != 1 {
		return
	}

	cname, ok := reply.Answer[0].(*dns.CNAME)
	if !ok {
		return
	}

	resp := &RecursiveResponseWriter{
		wr: wr,
	}

	cnameQ := &dns.Msg{}
	cnameQ.SetQuestion(cname.Target, q.Qtype)
	util.SetQueryDepth(cnameQ, queryDepth+1)

	h.mux.ServeDNS(resp, cnameQ)

	if resp.reply != nil && resp.reply.Rcode == dns.RcodeSuccess {
		reply.Answer = append(reply.Answer, resp.reply.Answer...)
	}
}
