package util

import (
	"encoding/hex"

	"github.com/miekg/dns"
)

func SetEDNS0(msg *dns.Msg, option []dns.EDNS0, paddingLen int, dnssecOk bool) *dns.OPT {
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
	edns0.SetDo(dnssecOk)

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
	"tcp":        true,
	"tcp-tls":    true,
	"tcp4":       true,
	"tcp6":       true,
	NetworkLocal: true,
}

func IsSecureProtocol(wr Addressable) bool {
	return secureProtocols[wr.LocalAddr().Network()]
}

func ApplyEDNS0Reply(query *dns.Msg, reply *dns.Msg, option []dns.EDNS0, wr Addressable) *dns.OPT {
	queryEdns0 := query.IsEdns0()
	if queryEdns0 == nil {
		if reply.Rcode > 0xF {
			// Unset extended RCODE if client doesn't speak EDNS0
			reply.Rcode = dns.RcodeServerFailure
		}
		return nil
	}

	paddingAllowed := RequireCookie || IsSecureProtocol(wr)
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
	return SetEDNS0(reply, option, paddingLen, queryEdns0.Do())
}

func ApplyEDNS0ReplyEarly(query *dns.Msg, reply *dns.Msg, wr Addressable) (bool, []dns.EDNS0) {
	queryEdns0 := query.IsEdns0()

	doRequireCookie := RequireCookie
	if IsSecureProtocol(wr) {
		doRequireCookie = false
	}

	if queryEdns0 == nil {
		if doRequireCookie {
			reply.Rcode = dns.RcodeRefused
			return false, nil
		}
		return true, nil
	}

	if queryEdns0.Version() != 0 {
		reply.Rcode = dns.RcodeBadVers
		SetEDNS0(reply, nil, 0, false)
		return false, nil
	}

	option := make([]dns.EDNS0, 0, 1)

	cookieMatch := false
	cookieFound := false

	for _, opt := range queryEdns0.Option {
		if opt.Option() != dns.EDNS0COOKIE {
			continue
		}

		cookieOpt, ok := opt.(*dns.EDNS0_COOKIE)
		if !ok {
			continue
		}

		binaryCookie, err := hex.DecodeString(cookieOpt.Cookie)
		if err != nil || binaryCookie == nil {
			continue
		}

		if len(binaryCookie) < ClientCookieLength {
			continue
		}

		clientCookie := binaryCookie[:ClientCookieLength]
		generatedServerCookie := GenerateServerCookie(false, clientCookie, wr)

		if len(binaryCookie) == ClientCookieLength+ServerCookieLength {
			receivedServerCookie := binaryCookie[ClientCookieLength:]

			cookieMatch = CookieCompare(receivedServerCookie, generatedServerCookie)
			if !cookieMatch { // If no match, try previous cookie
				previousServerCookie := GenerateServerCookie(true, clientCookie, wr)
				cookieMatch = CookieCompare(receivedServerCookie, previousServerCookie)
			}
		}

		cookieFound = true
		option = append(option, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: hex.EncodeToString(append(clientCookie, generatedServerCookie...)),
		})
		break
	}

	if doRequireCookie && !cookieMatch {
		if cookieFound {
			reply.Rcode = dns.RcodeBadCookie
		} else {
			reply.Rcode = dns.RcodeRefused
		}
		SetEDNS0(reply, option, 0, queryEdns0.Do())
		return false, option
	}

	return true, option
}
