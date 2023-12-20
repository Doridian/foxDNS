package simple

import (
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type Handler interface {
	// USE dns.ResponseWriter READ ONLY
	HandleQuestion(q dns.Question, wr dns.ResponseWriter) (recs []dns.RR, nxdomain bool)

	util.DNSHandler
}
