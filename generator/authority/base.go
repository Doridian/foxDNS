package authority

import (
	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type AuthorityHandler struct {
	soa   []dns.RR
	ns    []dns.RR
	zone  string
	Child simple.Handler
}

func fillAuthHeader(rr dns.RR, rtype uint16, zone string) dns.RR {
	return util.FillHeader(rr, zone, rtype, 300)
}

func NewAuthorityHandler(zone string, nsList []string, mbox string) *AuthorityHandler {
	hdl := &AuthorityHandler{}

	zone = dns.CanonicalName(zone)

	hdl.zone = zone
	hdl.ns = make([]dns.RR, 0, len(nsList))
	hdl.soa = []dns.RR{
		fillAuthHeader(&dns.SOA{
			Ns:      dns.CanonicalName(nsList[0]),
			Mbox:    dns.CanonicalName(mbox),
			Serial:  2022010169,
			Refresh: 43200,
			Retry:   3600,
			Expire:  86400,
			Minttl:  300,
		}, dns.TypeSOA, zone),
	}

	for _, ns := range nsList {
		hdl.ns = append(hdl.ns, fillAuthHeader(&dns.NS{
			Ns: dns.CanonicalName(ns),
		}, dns.TypeNS, zone))
	}

	return hdl
}

func (r *AuthorityHandler) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetRcode(msg, dns.RcodeSuccess)
	reply.Authoritative = true

	util.SetEDNS0(reply)

	q := msg.Question[0]
	if q.Qclass != dns.ClassINET {
		reply.Rcode = dns.RcodeRefused
		_ = wr.WriteMsg(reply)
		return
	}

	q.Name = dns.CanonicalName(q.Name)

	if q.Name == r.zone {
		switch q.Qtype {
		case dns.TypeSOA:
			reply.Answer = r.soa
		case dns.TypeNS:
			reply.Answer = r.ns
		}
	}

	if r.Child != nil && len(reply.Answer) < 1 {
		var nxdomain bool
		reply.Answer, nxdomain = r.Child.HandleQuestion(q, wr)
		util.SetHandlerName(wr, r.Child)
		if nxdomain {
			reply.Rcode = dns.RcodeNameError
		}

		if len(reply.Answer) < 1 {
			reply.Ns = r.soa
		}
	} else {
		util.SetHandlerName(wr, r)
	}

	_ = wr.WriteMsg(reply)
}

func (r *AuthorityHandler) Register(mux *dns.ServeMux) {
	mux.Handle(r.zone, r)
}

func (r *AuthorityHandler) Refresh() error {
	return nil
}

func (r *AuthorityHandler) Start() error {
	return nil
}

func (r *AuthorityHandler) Stop() error {
	return nil
}

func (r *AuthorityHandler) GetName() string {
	return "authority"
}
