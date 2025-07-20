package util

import (
	"github.com/miekg/dns"
)

const (
// EDNS0QDEPTH uint16 = iota + dns.EDNS0LOCALSTART
)

func GetEDNS0LocalOpt(msg *dns.Msg, code uint16) *dns.EDNS0_LOCAL {
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		return nil
	}

	for _, opt := range edns0.Option {
		if opt.Option() == code {
			edns0Local, ok := opt.(*dns.EDNS0_LOCAL)
			if ok {
				return edns0Local
			}
		}
	}

	return nil
}
