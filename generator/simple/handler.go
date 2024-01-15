package simple

import (
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type Handler interface {
	HandleQuestion(q *dns.Question, wr util.SimpleDNSResponseWriter) (recs []dns.RR, nxdomain bool)

	util.DNSHandler
}
