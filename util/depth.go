package util

import (
	"encoding/binary"

	"github.com/miekg/dns"
)

const NetworkLocal = "local"

const (
	EDNS0QDEPTH uint16 = iota + dns.EDNS0LOCALSTART
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

func SetQueryDepth(msg *dns.Msg, depth uint64) {
	SetEDNS0(msg, []dns.EDNS0{
		&dns.EDNS0_LOCAL{
			Code: EDNS0QDEPTH,
			Data: binary.BigEndian.AppendUint64(nil, uint64(depth)),
		},
	}, 0, false)
}

func GetQueryDepth(msg *dns.Msg, wr Addressable) uint64 {
	if wr.Network() != NetworkLocal {
		return 0
	}

	edns0 := GetEDNS0LocalOpt(msg, EDNS0QDEPTH)
	if edns0 == nil {
		return 0
	}

	return binary.BigEndian.Uint64(edns0.Data)
}
