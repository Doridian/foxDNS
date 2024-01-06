package util

import (
	"encoding/hex"

	"github.com/miekg/dns"
)

func SetEDNS0(msg *dns.Msg, option []dns.EDNS0, paddingLen int) *dns.OPT {
	if option == nil {
		option = []dns.EDNS0{}
	}

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

func ApplyEDNS0Reply(query *dns.Msg, reply *dns.Msg, option []dns.EDNS0, wr dns.ResponseWriter, requireCookie bool) *dns.OPT {
	queryEdns0 := query.IsEdns0()
	if queryEdns0 == nil {
		return nil
	}

	paddingAllowed := requireCookie || IsSecureProtocol(wr.LocalAddr().Network())
	clientRequestedPadding := false

	for _, opt := range queryEdns0.Option {
		if opt.Option() != dns.EDNS0PADDING {
			continue
		}
		clientRequestedPadding = true
		break
	}

	paddingLen := 0
	if paddingAllowed && clientRequestedPadding {
		paddingLen = 468
	}
	return SetEDNS0(reply, option, paddingLen)
}

func ApplyEDNS0ReplyEarly(query *dns.Msg, reply *dns.Msg, wr dns.ResponseWriter, requireCookie bool) (bool, []dns.EDNS0) {
	queryEdns0 := query.IsEdns0()
	option := make([]dns.EDNS0, 0, 1)

	if IsSecureProtocol(wr.LocalAddr().Network()) {
		requireCookie = false
	}

	if queryEdns0 == nil {
		if requireCookie {
			reply.Rcode = dns.RcodeRefused
			return false, nil
		}
		return true, nil
	}

	if queryEdns0.Version() != 0 {
		reply.Rcode = dns.RcodeBadVers
		SetEDNS0(reply, nil, 0)
		return false, nil
	}

	var cookieMatch bool
	var cookieFound bool

	for _, opt := range queryEdns0.Option {
		if opt.Option() != dns.EDNS0COOKIE {
			continue
		}

		cookieOpt, ok := opt.(*dns.EDNS0_COOKIE)
		if !ok {
			continue
		}
		if len(cookieOpt.Cookie) < 16 {
			continue
		}

		binaryCookie, err := hex.DecodeString(cookieOpt.Cookie)
		if err != nil || binaryCookie == nil {
			continue
		}

		clientCookie := binaryCookie[:8]
		receivedServerCookie := binaryCookie[8:]

		generatedServerCookie := GenerateServerCookie(false, clientCookie, wr)
		cookieMatch = CookieCompare(receivedServerCookie, generatedServerCookie)
		if !cookieMatch { // If no match, try previous cookie
			previousServerCookie := GenerateServerCookie(true, clientCookie, wr)
			cookieMatch = CookieCompare(receivedServerCookie, previousServerCookie)
		}

		cookieFound = true
		option = append(option, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: hex.EncodeToString(append(clientCookie, generatedServerCookie...)),
		})
		break
	}

	if requireCookie && !cookieMatch {
		if cookieFound {
			reply.Rcode = dns.RcodeBadCookie
		} else {
			reply.Rcode = dns.RcodeRefused
		}
		SetEDNS0(reply, option, 0)
		return false, option
	}

	return true, option
}
