package blackhole

import (
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type Generator struct {
	reason string
}

func New(reason string) *Generator {
	return &Generator{
		reason: reason,
	}
}

func (r *Generator) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	reply := &dns.Msg{
		Compress: true,
		MsgHdr: dns.MsgHdr{
			Authoritative: true,
		},
	}
	reply.SetRcode(msg, dns.RcodeNameError)
	ok, option := util.ApplyEDNS0ReplyEarly(msg, reply, wr, false)
	if ok {
		option = append(option, &dns.EDNS0_EDE{
			InfoCode:  dns.ExtendedErrorCodeFiltered,
			ExtraText: r.reason,
		})
		util.ApplyEDNS0Reply(msg, reply, option, wr, false)
	}
	util.SetHandlerName(wr, r)
	_ = wr.WriteMsg(reply)
}

func (r *Generator) GetName() string {
	return "blackhole"
}
