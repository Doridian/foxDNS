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
