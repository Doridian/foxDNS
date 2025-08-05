package handler

import (
	"errors"
	"net"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type RecursiveResponseWriter struct {
	wr    util.Addressable
	reply *dns.Msg
}

func NewRecursiveResponseWriter(wr util.Addressable) *RecursiveResponseWriter {
	return &RecursiveResponseWriter{
		wr: wr,
	}
}

func (c *RecursiveResponseWriter) Close() error {
	return errors.New("unimplemented")
}

func (c *RecursiveResponseWriter) Hijack() {
	panic("unimplemented")
}

func (c *RecursiveResponseWriter) LocalAddr() net.Addr {
	return &util.NetworkLocalAddr{
		Parent: c.wr.LocalAddr(),
	}
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

func (c *RecursiveResponseWriter) GetMsg() *dns.Msg {
	return c.reply
}

func (c *RecursiveResponseWriter) WriteMsg(reply *dns.Msg) error {
	if c.reply != nil {
		return errors.New("cannot write multiple messages to RecursiveResponseWriter")
	}
	c.reply = reply
	return nil
}
