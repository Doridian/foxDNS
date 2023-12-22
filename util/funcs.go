package util

import (
	"net"

	"github.com/miekg/dns"
)

func ExtractIP(addr net.Addr) net.IP {
	switch convAddr := addr.(type) {
	case *net.TCPAddr:
		return convAddr.IP
	case *net.UDPAddr:
		return convAddr.IP
	case *net.IPAddr:
		return convAddr.IP
	default:
		return net.IPv4(0, 0, 0, 0)
	}
}

func IPIsPrivateOrLocal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

func FillHeader(rr dns.RR, name string, rtype uint16, ttl uint32) dns.RR {
	hdr := rr.Header()
	hdr.Ttl = ttl
	hdr.Class = dns.ClassINET
	hdr.Rrtype = rtype
	hdr.Name = name
	hdr.Rdlength = 0
	return rr
}

func SetEDNS0(msg *dns.Msg) {
	msg.SetEdns0(UDPSize, false)
}

type DNSHandler interface {
	GetName() string
}

type DNSHandlerWrapper interface {
	SetHandlerName(name string)
}

func SetHandlerName(wr dns.ResponseWriter, hdl DNSHandler) {
	wrappedHandler, ok := wr.(DNSHandlerWrapper)
	if ok {
		wrappedHandler.SetHandlerName(hdl.GetName())
	}
}

func IsBadQuery(q *dns.Question) bool {
	return q.Qclass != dns.ClassINET || q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR || q.Qtype == dns.TypeMAILA || q.Qtype == dns.TypeMAILB || q.Qtype == dns.TypeANY
}
