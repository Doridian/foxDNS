package resolver

import (
	"log"
	"time"

	"github.com/Doridian/foxDNS/handler"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (h *Handler) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	startTime := time.Now()

	reply := &dns.Msg{
		Compress: true,
		MsgHdr: dns.MsgHdr{
			Authoritative:      false,
			RecursionAvailable: true,
		},
	}

	reply.SetRcode(msg, dns.RcodeServerFailure)

	ok, option := util.ApplyEDNS0ReplyEarly(msg, reply, wr, h.RequireCookie)
	if !ok {
		_ = wr.WriteMsg(reply)
		return
	}

	var upstreamReplyEdns0 *dns.OPT

	defer func() {
		replyEdns0 := util.ApplyEDNS0Reply(msg, reply, option, wr, h.RequireCookie)
		if replyEdns0 != nil && upstreamReplyEdns0 != nil && upstreamReplyEdns0.Version() == replyEdns0.Version() {
			for _, upstreamOpt := range upstreamReplyEdns0.Option {
				if upstreamOpt.Option() != dns.EDNS0EDE {
					continue
				}

				replyEdns0.Option = append(replyEdns0.Option, upstreamOpt)
				break
			}
		}

		if replyEdns0 == nil && reply.Rcode > 0xF {
			// Unset extended RCODE if client doesn't speak EDNS0
			reply.Rcode = dns.RcodeServerFailure
		}

		_ = wr.WriteMsg(reply)
	}()

	if len(msg.Question) == 0 {
		reply.Rcode = dns.RcodeFormatError
		return
	}

	if !util.IsLocalQuery(wr) && len(msg.Question) > 1 {
		reply.Rcode = dns.RcodeFormatError
		return
	}

	q := &msg.Question[0]
	if util.IsBadQuery(q) {
		reply.Rcode = dns.RcodeRefused
		return
	}

	defer handler.MeasureQuery(startTime, reply, h.GetName())

	q.Name = dns.CanonicalName(q.Name)

	cacheResult, matchType, upstreamReply, err := h.getOrAddCache(q, false, 1)
	if err != nil {
		log.Printf("Error handling DNS request: %v", err)
		return
	}
	cacheResults.WithLabelValues(cacheResult, matchType).Inc()

	msgEdns0 := msg.IsEdns0()
	if msgEdns0 != nil && msgEdns0.Do() {
		reply.Answer = upstreamReply.Answer
	} else {
		newAnswers := make([]dns.RR, 0, len(upstreamReply.Answer))
		for _, rr := range upstreamReply.Answer {
			rrType := rr.Header().Rrtype
			if rrType == dns.TypeRRSIG || rrType == dns.TypeNSEC || rrType == dns.TypeNSEC3 {
				continue
			}
			newAnswers = append(newAnswers, rr)
		}
		reply.Answer = newAnswers
	}

	reply.Rcode = upstreamReply.Rcode
	reply.Ns = upstreamReply.Ns
	upstreamReplyEdns0 = upstreamReply.IsEdns0()
}
