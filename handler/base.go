package handler

import (
	"net"

	"github.com/miekg/dns"
)

type Generator interface {
	GetName() string
	HandleQuestion(q *dns.Question, remoteIP net.IP) (answer []dns.RR, ns []dns.RR, edns0Opts []dns.EDNS0, rcode int)

	Loadable
}

type Loadable interface {
	Refresh() error
	Start() error
	Stop() error
}
