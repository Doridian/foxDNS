package authority

import (
	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type AuthConfig struct {
	Nameservers []string
	Mbox        string
	SOATtl      uint32
	NSTtl       uint32
	Serial      uint32
	Refresh     uint32
	Retry       uint32
	Expire      uint32
	Minttl      uint32
}

type AuthorityHandler struct {
	soa   []dns.RR
	ns    []dns.RR
	zone  string
	Child simple.Handler
}

func GetDefaultAuthorityConfig() AuthConfig {
	return AuthConfig{
		SOATtl:  300,
		NSTtl:   300,
		Serial:  2022010169,
		Refresh: 43200,
		Retry:   3600,
		Expire:  86400,
		Minttl:  300,
	}
}

func FillAuthHeader(rr dns.RR, rtype uint16, zone string, ttl uint32) dns.RR {
	return util.FillHeader(rr, zone, rtype, ttl)
}

func NewAuthorityHandler(zone string, config AuthConfig) *AuthorityHandler {
	hdl := &AuthorityHandler{}

	zone = dns.CanonicalName(zone)

	hdl.zone = zone
	hdl.ns = make([]dns.RR, 0, len(config.Nameservers))
	hdl.soa = []dns.RR{
		FillAuthHeader(&dns.SOA{
			Ns:      dns.CanonicalName(config.Nameservers[0]),
			Mbox:    dns.CanonicalName(config.Mbox),
			Serial:  config.Serial,
			Refresh: config.Refresh,
			Retry:   config.Retry,
			Expire:  config.Expire,
			Minttl:  config.Minttl,
		}, dns.TypeSOA, zone, config.SOATtl),
	}

	for _, ns := range config.Nameservers {
		hdl.ns = append(hdl.ns, FillAuthHeader(&dns.NS{
			Ns: dns.CanonicalName(ns),
		}, dns.TypeNS, zone, config.NSTtl))
	}

	return hdl
}

func (r *AuthorityHandler) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	reply := &dns.Msg{
		Compress: true,
		MsgHdr: dns.MsgHdr{
			Authoritative: true,
		},
	}
	reply.SetRcode(msg, dns.RcodeSuccess)

	defer func() {
		util.ApplyEDNS0ReplyIfNeeded(msg, reply, []dns.EDNS0{}, wr)
		_ = wr.WriteMsg(reply)
	}()

	q := &msg.Question[0]
	if q.Qclass != dns.ClassINET {
		reply.Rcode = dns.RcodeRefused
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
