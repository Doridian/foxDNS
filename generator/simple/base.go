package simple

import (
	"github.com/Doridian/foxDNS/util"
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
		util.SetHandlerName(wr, r)
		reply.Rcode = dns.RcodeRefused
		wr.WriteMsg(reply)
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

func (r *Generator) GetName() string {
	return "simple"
}
