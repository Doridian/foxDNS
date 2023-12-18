package simple

import (
	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type Generator struct {
	zone  string
	Child Handler
}

func New(zone string) *Generator {
	hdl := &Generator{
		zone: dns.CanonicalName(zone),
	}

	return hdl
}

func (r *Generator) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetRcode(msg, dns.RcodeSuccess)
	reply.Authoritative = true

	util.SetEDNS0(reply)

	q := msg.Question[0]
	if q.Qclass != dns.ClassINET {
		reply.Rcode = dns.RcodeRefused
		wr.WriteMsg(reply)
		return
	}

	q.Name = dns.CanonicalName(q.Name)

	reply.Answer = r.Child.HandleQuestion(q, wr)

	if len(reply.Answer) == 0 {
		q.Qtype = dns.TypeSOA
		q.Name = r.zone
		reply.Ns = r.Child.HandleQuestion(q, wr)
	}

	wr.WriteMsg(reply)
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
