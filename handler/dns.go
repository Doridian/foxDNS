package handler

import (
	"log"
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
			RecursionAvailable: h.recursionAvailable,
		},
	}
	reply.SetRcode(msg, dns.RcodeSuccess)

	ok, edns0Options := util.ApplyEDNS0ReplyEarly(msg, reply, wr, h.requireCookie)
	if !ok {
		_ = wr.WriteMsg(reply)
		return
	}

	defer func() {
		util.ApplyEDNS0Reply(msg, reply, edns0Options, wr, h.requireCookie)
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

	q.Name = dns.CanonicalName(q.Name)
	remoteIP := util.ExtractIP(wr.RemoteAddr())
	recurse := msg.RecursionDesired && h.recursionAvailable

	reply.Answer = nil
	if h.authoritative && q.Name == h.zone {
		switch q.Qtype {
		case dns.TypeSOA:
			reply.Answer = h.soa
		case dns.TypeNS:
			reply.Answer = h.ns
		case dns.TypeDNSKEY:
			reply.Answer = []dns.RR{}
			if h.zskDNSKEY != nil {
				reply.Answer = append(reply.Answer, h.zskDNSKEY)
			}
			if h.kskDNSKEY != nil {
				reply.Answer = append(reply.Answer, h.kskDNSKEY)
			}
		}
	}
	if len(reply.Answer) == 0 {
		var childEdns0 []dns.EDNS0
		reply.Answer, reply.Ns, childEdns0, reply.Rcode = h.child.HandleQuestion(q, recurse, remoteIP)
		if (reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError) && len(reply.Answer) == 0 && len(reply.Ns) == 0 {
			reply.Ns = h.soa
		}
		if childEdns0 != nil {
			edns0Options = append(edns0Options, childEdns0...)
		}
	}

	if recurse && queryDepth < util.MaxRecursionDepth {
		h.resolveIfCNAME(reply, msg.Question, wr)
		// TODO: Resolve NS referrals
	}

	if !util.IsLocalQuery(wr) && (reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError) {
		msgEdns0 := msg.IsEdns0()
		if msgEdns0 != nil && msgEdns0.Do() {
			signer, err := h.signResponse(q, reply.Answer)
			if err != nil {
				log.Printf("Error signing record for %s: %v", reply.Answer[0].Header().Name, err)
			} else if signer != nil {
				reply.Answer = append(reply.Answer, signer)
			}
		} else {
			newAnswers := make([]dns.RR, 0, len(reply.Answer))
			for _, rr := range reply.Answer {
				rrType := rr.Header().Rrtype
				if rrType == dns.TypeRRSIG || rrType == dns.TypeNSEC || rrType == dns.TypeNSEC3 {
					continue
				}
				newAnswers = append(newAnswers, rr)
			}
			reply.Answer = newAnswers
		}
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

	queriesProcessed.WithLabelValues(dns.TypeToString[q.Qtype], rcode, h.child.GetName(), extendedRCode).Inc()
	queryProcessingTime.WithLabelValues(h.child.GetName()).Observe(duration.Seconds())
}
