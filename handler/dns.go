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

	q.Name = dns.CanonicalName(q.Name)
	remoteIP := util.ExtractIP(wr.RemoteAddr())
	recurse := msg.RecursionDesired && queryDepth < util.MaxRecursionDepth

	dnssec := msg.IsEdns0() != nil && msg.IsEdns0().Do()

	var childEdns0 []dns.EDNS0
	reply.Answer, reply.Ns, childEdns0, reply.Rcode = h.child.HandleQuestion(q, recurse, dnssec, remoteIP)
	if childEdns0 != nil {
		edns0Options = append(edns0Options, childEdns0...)
	}

	if recurse {
		h.resolveIfCNAME(reply, msg.Question, wr)
		// TODO: Resolve NS referrals
	}

	if !util.IsLocalQuery(wr) && (reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError) && dnssec {
		signer, err := h.signResponse(q, reply.Answer)
		if err != nil {
			log.Printf("Error signing record for %s: %v", reply.Answer[0].Header().Name, err)
		} else if signer != nil {
			reply.Answer = append(reply.Answer, signer)
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
