package authority

import (
	"github.com/FoxDenHome/foxdns/generator/simple"
	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type authData struct {
	soa []dns.RR
	ns  []dns.RR
}

type AuthorityHandler struct {
	zones map[string]*authData
	Child simple.Handler
}

func fillAuthHeader(rr dns.RR, rtype uint16, zone string) dns.RR {
	return util.FillHeader(rr, zone, rtype, 86400)
}

func NewAuthorityHandler(zones []string, nsList []string, mbox string) *AuthorityHandler {
	hdl := &AuthorityHandler{
		zones: make(map[string]*authData),
	}

	for _, zone := range zones {
		zone = dns.CanonicalName(zone)

		ad := &authData{
			ns: make([]dns.RR, 0, len(nsList)),
			soa: []dns.RR{
				fillAuthHeader(&dns.SOA{
					Ns:      dns.CanonicalName(nsList[0]),
					Mbox:    dns.CanonicalName(mbox),
					Serial:  2022010169,
					Refresh: 43200,
					Retry:   3600,
					Expire:  86400,
					Minttl:  60,
				}, dns.TypeSOA, zone),
			},
		}

		for _, ns := range nsList {
			ad.ns = append(ad.ns, fillAuthHeader(&dns.NS{
				Ns: dns.CanonicalName(ns),
			}, dns.TypeNS, zone))
		}

		hdl.zones[zone] = ad
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
		wr.WriteMsg(reply)
		return
	}

	q.Name = dns.CanonicalName(q.Name)

	ad := r.zones[q.Name]
	if ad != nil {
		switch q.Qtype {
		case dns.TypeSOA:
			reply.Answer = ad.soa
		case dns.TypeNS:
			reply.Answer = ad.ns
		}
	}

	if r.Child != nil && len(reply.Answer) < 1 {
		reply.Answer = r.Child.HandleQuestion(q, wr)
	}

	wr.WriteMsg(reply)
}

func (r *AuthorityHandler) Register(mux *dns.ServeMux) {
	for zone := range r.zones {
		mux.Handle(zone, r)
	}
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
