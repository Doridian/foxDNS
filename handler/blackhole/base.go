package blackhole

import (
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

const BlackholeHost = "blackhole.foxdns.doridian.net."

type Generator struct {
	soa   []dns.RR
	edns0 []dns.EDNS0
}

func New(reason string) *Generator {
	return &Generator{
		soa: []dns.RR{
			&dns.SOA{
				Hdr: dns.RR_Header{
					Name:   BlackholeHost,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Ns:      BlackholeHost,
				Mbox:    BlackholeHost,
				Serial:  666,
				Refresh: 3600,
				Retry:   3600,
				Expire:  3600,
				Minttl:  3600,
			},
		},
		edns0: []dns.EDNS0{&dns.EDNS0_EDE{
			InfoCode:  dns.ExtendedErrorCodeFiltered,
			ExtraText: reason,
		}},
	}
}

func (r *Generator) HandleQuestion(_ []dns.Question, _ bool, _ bool, _ util.Addressable) ([]dns.RR, []dns.RR, []dns.EDNS0, int, string) {
	return nil, r.soa, r.edns0, dns.RcodeNameError, ""
}

func (r *Generator) GetName() string {
	return "blackhole"
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
