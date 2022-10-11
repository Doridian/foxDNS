package authority

import "github.com/miekg/dns"

type AuthoritativeHandler interface {
	// USE dns.ResponseWriter READ ONLY
	HandleQuestion(q dns.Question, wr dns.ResponseWriter) []dns.RR
}
