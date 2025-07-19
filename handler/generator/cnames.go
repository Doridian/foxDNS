package generator

import (
	"errors"
	"net"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type CNAMEProxyResponseWriter struct {
	wr    util.Addressable
	reply *dns.Msg
}

func (h *Handler) resolveIfCNAME(reply *dns.Msg, q *dns.Question, wr util.Addressable) {
	// There can only legally ever be 1 CNAME, so dont even bother checking is multiple records
	if reply.Rcode != dns.RcodeSuccess || q.Qtype == dns.TypeCNAME || len(reply.Answer) != 1 {
		return
	}

	cname, ok := reply.Answer[0].(*dns.CNAME)
	if !ok {
		return
	}

	resp := &CNAMEProxyResponseWriter{
		wr: wr,
	}

	cnameQ := &dns.Msg{}
	cnameQ.SetQuestion(cname.Target, q.Qtype)

	h.mux.ServeDNS(resp, cnameQ)

	if resp.reply != nil && resp.reply.Rcode == dns.RcodeSuccess {
		reply.Answer = append(reply.Answer, resp.reply.Answer...)
	}
}

func (c *CNAMEProxyResponseWriter) Close() error {
	return errors.New("unimplemented")
}

func (c *CNAMEProxyResponseWriter) Hijack() {
	panic("unimplemented")
}

func (c *CNAMEProxyResponseWriter) LocalAddr() net.Addr {
	return c.wr.LocalAddr()
}

func (c *CNAMEProxyResponseWriter) Network() string {
	return c.wr.Network()
}

func (c *CNAMEProxyResponseWriter) RemoteAddr() net.Addr {
	return c.wr.RemoteAddr()
}

func (c *CNAMEProxyResponseWriter) TsigStatus() error {
	return errors.New("unimplemented")
}

func (c *CNAMEProxyResponseWriter) TsigTimersOnly(bool) {
	// no-op
}

func (c *CNAMEProxyResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("unimplemented")
}

func (c *CNAMEProxyResponseWriter) WriteMsg(reply *dns.Msg) error {
	if c.reply != nil {
		return errors.New("cannot write multiple messages to CNAMEProxyResponseWriter")
	}
	c.reply = reply
	return nil
}
