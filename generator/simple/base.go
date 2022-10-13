package simple

import (
	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type Generator struct {
	zones map[string]bool
	Child Handler
}

func New(zones []string) *Generator {
	hdl := &Generator{
		zones: make(map[string]bool),
	}

	for _, zone := range zones {
		zone = dns.CanonicalName(zone)
		hdl.zones[zone] = true
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

	wr.WriteMsg(reply)
}

func (r *Generator) Register(mux *dns.ServeMux) {
	for zone := range r.zones {
		mux.Handle(zone, r)
	}
}
