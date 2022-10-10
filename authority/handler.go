package authority

import "github.com/miekg/dns"

type AuthoritativeHandler interface {
	HandleQuestion(q dns.Question) []dns.RR
}
