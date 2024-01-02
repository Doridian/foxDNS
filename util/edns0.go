package util

import (
	"encoding/hex"

	"github.com/miekg/dns"
)

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

var secureProtocols = map[string]bool{
	"tcp":     true,
	"tcp-tls": true,
	"tcp4":    true,
	"tcp6":    true,
}

func IsSecureProtocol(proto string) bool {
	return secureProtocols[proto]
}

func ApplyEDNS0ReplyIfNeeded(query *dns.Msg, reply *dns.Msg, option []dns.EDNS0, wr dns.ResponseWriter) *dns.OPT {
	queryEdns0 := query.IsEdns0()
	if queryEdns0 == nil {
		return nil
	}

	// TODO: Allow padding for UDP with COOKIE set?
	paddingAllowed := IsSecureProtocol(wr.LocalAddr().Network())
	clientRequestedPadding := false

	if queryEdns0.Version() == 0 {
		for _, opt := range queryEdns0.Option {
			switch opt.Option() {
			case dns.EDNS0PADDING:
				clientRequestedPadding = true
			case dns.EDNS0COOKIE:
				cookieOpt, ok := opt.(*dns.EDNS0_COOKIE)
				if !ok {
					continue
				}
				if len(cookieOpt.Cookie) < 16 {
					continue
				}
				clientCookie := cookieOpt.Cookie[:16] // hex encoded
				option = append(option, &dns.EDNS0_COOKIE{
					Code:   dns.EDNS0COOKIE,
					Cookie: clientCookie + hex.EncodeToString(GenerateServerCookie(clientCookie, wr)),
				})
			}
		}
	} else {
		reply.Answer = []dns.RR{}
		reply.Ns = []dns.RR{}
		reply.Extra = []dns.RR{}
		reply.Rcode = dns.RcodeBadVers
		option = []dns.EDNS0{}
	}

	paddingLen := 0
	if paddingAllowed && clientRequestedPadding {
		paddingLen = 468
	}
	return SetEDNS0(reply, option, paddingLen)
}
