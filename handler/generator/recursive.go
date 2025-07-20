package generator

import (
	"errors"
	"net"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (h *Handler) subQuery(reply *dns.Msg, questions []dns.Question, q dns.Question, wr util.Addressable) {
	for _, oldQ := range questions {
		if oldQ.Name == q.Name && oldQ.Qtype == q.Qtype && oldQ.Qclass == q.Qclass {
			return // Already queried this one
		}
	}

	resp := &RecursiveResponseWriter{
		wr: wr,
	}

	subQ := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1, len(questions)+1),
	}
	subQ.Question[0] = q
	subQ.Question = append(subQ.Question, questions...)

	h.mux.ServeDNS(resp, subQ)

	if resp.reply != nil && resp.reply.Rcode == dns.RcodeSuccess {
		reply.Answer = append(reply.Answer, resp.reply.Answer...)
	}
}

type RecursiveResponseWriter struct {
	wr    util.Addressable
	reply *dns.Msg
}

func (c *RecursiveResponseWriter) Close() error {
	return errors.New("unimplemented")
}

func (c *RecursiveResponseWriter) Hijack() {
	panic("unimplemented")
}

func (c *RecursiveResponseWriter) LocalAddr() net.Addr {
	return c.wr.LocalAddr()
}

func (c *RecursiveResponseWriter) Network() string {
	return util.NetworkLocal
}

func (c *RecursiveResponseWriter) RemoteAddr() net.Addr {
	return c.wr.RemoteAddr()
}

func (c *RecursiveResponseWriter) TsigStatus() error {
	return errors.New("unimplemented")
}

func (c *RecursiveResponseWriter) TsigTimersOnly(bool) {
	// no-op
}

func (c *RecursiveResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("unimplemented")
}

func (c *RecursiveResponseWriter) WriteMsg(reply *dns.Msg) error {
	if c.reply != nil {
		return errors.New("cannot write multiple messages to CNAMEProxyResponseWriter")
	}
	c.reply = reply
	return nil
}
