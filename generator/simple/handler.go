package simple

import "github.com/miekg/dns"

type Handler interface {
	// USE dns.ResponseWriter READ ONLY
	HandleQuestion(q dns.Question, wr dns.ResponseWriter) (recs []dns.RR, nxdomain bool)

	GetName() string
}
