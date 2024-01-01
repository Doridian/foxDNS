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

func SetEDNS0(msg *dns.Msg, option []dns.EDNS0, paddingLen int) *dns.OPT {
	edns0 := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
		Option: option,
	}
	edns0.SetUDPSize(UDPSize)

	msg.Extra = append(msg.Extra, edns0)

	if paddingLen > 0 {
		edns0Padding := &dns.EDNS0_PADDING{}
		edns0.Option = append(edns0.Option, edns0Padding)

		padMissing := msg.Len() % paddingLen
		if padMissing > 0 {
			edns0Padding.Padding = make([]byte, paddingLen-padMissing)
		}
	}

	return edns0
}

var paddingAllowedProtocols = map[string]bool{
	"tcp":     true,
	"tcp-tls": true,
	"tcp4":    true,
	"tcp6":    true,
}

func ApplyEDNS0ReplyIfNeeded(query *dns.Msg, reply *dns.Msg, option []dns.EDNS0, wr dns.ResponseWriter) *dns.OPT {
	queryEdns0 := query.IsEdns0()
	if queryEdns0 == nil {
		return nil
	}

	// TODO: Allow padding for UDP with COOKIE set
	paddingAllowed := paddingAllowedProtocols[wr.LocalAddr().Network()]
	clientRequestedPadding := false

	if queryEdns0.Version() == 0 {
		for _, opt := range queryEdns0.Option {
			if opt.Option() == dns.EDNS0PADDING {
				clientRequestedPadding = true
				break
			}
		}
	} else {
		reply.Answer = []dns.RR{}
		reply.Ns = []dns.RR{}
		reply.Extra = []dns.RR{}
		reply.Rcode = dns.RcodeBadVers
		option = []dns.EDNS0{}
		clientRequestedPadding = paddingAllowed
	}

	paddingLen := 0
	if paddingAllowed && clientRequestedPadding {
		paddingLen = 468
	}
	return SetEDNS0(reply, option, paddingLen)
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
