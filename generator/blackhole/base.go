package blackhole

import (
	"net"

	"github.com/miekg/dns"
)

type Generator struct {
	reason string
}

func New(reason string) *Generator {
	return &Generator{
		reason: reason,
	}
}

func (r *Generator) HandleQuestion(q *dns.Question, remoteIP net.IP) (recs []dns.RR, ns []dns.RR, edns0Opts []dns.EDNS0, rcode int) {
	return nil, nil, []dns.EDNS0{&dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeFiltered,
		ExtraText: r.reason,
	}}, dns.RcodeNameError
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
