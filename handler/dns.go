package handler

import (
	"time"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (h *Handler) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	startTime := time.Now()

	reply := &dns.Msg{
		Compress: true,
		MsgHdr: dns.MsgHdr{
			Authoritative:      h.authoritative,
			RecursionAvailable: util.MaxRecursionDepth > 0,
		},
	}
	reply.SetRcode(msg, dns.RcodeSuccess)

	ok, edns0Options := util.ApplyEDNS0ReplyEarly(msg, reply, wr)
	if !ok {
		_ = wr.WriteMsg(reply)
		return
	}

	defer func() {
		util.ApplyEDNS0Reply(msg, reply, edns0Options, wr)
		_ = wr.WriteMsg(reply)
	}()

	if len(msg.Question) == 0 {
		reply.Rcode = dns.RcodeFormatError
		return
	}

	queryDepth := 0
	if util.IsLocalQuery(wr) {
		queryDepth = len(msg.Question) - 1
	} else if len(msg.Question) > 1 {
		reply.Rcode = dns.RcodeFormatError
		return
	}

	q := &msg.Question[0]
	if util.IsBadQuery(q) {
		reply.Rcode = dns.RcodeRefused
		return
	}

	var handlerName string
	q.Name = dns.CanonicalName(q.Name)
	recurse := msg.RecursionDesired && queryDepth < util.MaxRecursionDepth
	dnssec := msg.IsEdns0() != nil && msg.IsEdns0().Do()

	var childEdns0 []dns.EDNS0
	reply.Answer, reply.Ns, childEdns0, reply.Rcode, handlerName = h.child.HandleQuestion(msg.Question, recurse, dnssec, wr)
	if childEdns0 != nil {
		edns0Options = append(edns0Options, childEdns0...)
	}

	duration := time.Since(startTime)

	rcode := dns.RcodeToString[reply.Rcode]
	if reply.Rcode == dns.RcodeSuccess && len(reply.Answer) == 0 {
		rcode = "NXRECORD"
	}

	extendedRCode := ""
	replyEdns0 := reply.IsEdns0()
	if replyEdns0 != nil {
		for _, opt := range replyEdns0.Option {
			if opt.Option() != dns.EDNS0EDE {
				continue
			}

			edeOpt, ok := opt.(*dns.EDNS0_EDE)
			if !ok {
				continue
			}
			extendedRCode = dns.ExtendedErrorCodeToString[edeOpt.InfoCode]
			break
		}
	}

	if handlerName == "" {
		handlerName = h.child.GetName()
	}

	queriesProcessed.WithLabelValues(dns.TypeToString[q.Qtype], rcode, handlerName, extendedRCode).Inc()
	queryProcessingTime.WithLabelValues(handlerName).Observe(duration.Seconds())
}
