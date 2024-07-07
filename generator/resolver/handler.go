package resolver

import (
	"log"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (r *Generator) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	util.SetHandlerName(wr, r)

	reply := &dns.Msg{
		Compress: true,
	}
	if len(msg.Question) != 1 {
		_ = wr.WriteMsg(reply.SetRcode(msg, dns.RcodeRefused))
		return
	}
	reply.SetRcode(msg, dns.RcodeServerFailure)

	ok, option := util.ApplyEDNS0ReplyEarly(msg, reply, wr, r.RequireCookie)
	if !ok {
		_ = wr.WriteMsg(reply)
		return
	}

	var upstreamReplyEdns0 *dns.OPT

	defer func() {
		replyEdns0 := util.ApplyEDNS0Reply(msg, reply, option, wr, r.RequireCookie)
		if replyEdns0 != nil && upstreamReplyEdns0 != nil && upstreamReplyEdns0.Version() == replyEdns0.Version() {
			replyEdns0.SetDo(upstreamReplyEdns0.Do())

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

	if r.AllowOnlyFromPrivate {
		ip := util.ExtractIP(wr.RemoteAddr())
		if !util.IPIsPrivateOrLocal(ip) {
			reply.RecursionAvailable = false
			reply.Rcode = dns.RcodeRefused
			return
		}
	}

	reply.RecursionAvailable = true

	q := &msg.Question[0]
	if util.IsBadQuery(q) {
		reply.Rcode = dns.RcodeRefused
		return
	}
	q.Name = dns.CanonicalName(q.Name)

	cacheResult, matchType, upstreamReply, err := r.getOrAddCache(q, false, 1)
	if err != nil {
		log.Printf("Error handling DNS request: %v", err)
		return
	}
	cacheResults.WithLabelValues(cacheResult, matchType).Inc()

	reply.Rcode = upstreamReply.Rcode
	reply.Answer = upstreamReply.Answer
	reply.Ns = upstreamReply.Ns
	upstreamReplyEdns0 = upstreamReply.IsEdns0()
}
