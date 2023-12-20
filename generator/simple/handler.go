package simple

import (
	"net"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type DNSResponseWriter interface {
	// LocalAddr returns the net.Addr of the server
	LocalAddr() net.Addr
	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr
}

type Handler interface {
	HandleQuestion(q *dns.Question, wr DNSResponseWriter) (recs []dns.RR, nxdomain bool)

	util.DNSHandler
}
