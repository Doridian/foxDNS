package simple

import (
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type Generator struct {
	zone          string
	Child         Handler
	RequireCookie bool
}

func New(zone string) *Generator {
	zone = dns.CanonicalName(zone)
	return &Generator{
		zone: zone,
	}
}

func (r *Generator) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	reply := &dns.Msg{
		Compress: true,
		MsgHdr: dns.MsgHdr{
			Authoritative: true,
		},
	}
	reply.SetRcode(msg, dns.RcodeSuccess)

	ok, option := util.ApplyEDNS0ReplyEarly(msg, reply, wr, r.RequireCookie)
	if !ok {
		_ = wr.WriteMsg(reply)
		return
	}

	defer func() {
		util.ApplyEDNS0Reply(msg, reply, option, wr, r.RequireCookie)
		_ = wr.WriteMsg(reply)
	}()

	q := &msg.Question[0]
	if util.IsBadQuery(q) {
		util.SetHandlerName(wr, r)
		reply.Rcode = dns.RcodeRefused
		return
	}

	q.Name = dns.CanonicalName(q.Name)

	var nxdomain bool
	reply.Answer, nxdomain = r.Child.HandleQuestion(q, wr)
	util.SetHandlerName(wr, r.Child)
	if nxdomain {
		reply.Rcode = dns.RcodeNameError
	}

	if len(reply.Answer) == 0 {
		q.Qtype = dns.TypeSOA
		q.Name = r.zone
		reply.Ns, _ = r.Child.HandleQuestion(q, wr)
	}
}

func (r *Generator) Register(mux *dns.ServeMux) {
	mux.Handle(r.zone, r)
}

func (r *Generator) Refresh() error {
	return nil
}

func (r *Generator) Start() error {
	return nil
}

func (r *Generator) Stop() error {
	return nil
}

func (r *Generator) GetName() string {
	return "simple"
}
