package resolver

import (
	"time"

	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

func (r *Resolver) exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	var conn *dns.Conn
	conn, err = r.acquireConn()
	if err != nil {
		r.returnConn(conn, err)
		return
	}

	resp, _, err = r.Client.ExchangeWithConn(m, conn)
	r.returnConn(conn, err)
	return
}

func (r *Resolver) exchangeWithRetry(q *dns.Question) (resp *dns.Msg, err error) {
	m := &dns.Msg{
		Question: []dns.Question{*q},
	}

	m.Id = dns.Id()
	m.Opcode = dns.OpcodeQuery
	m.RecursionDesired = true

	util.SetEDNS0(m)

	for i := r.Retries; i > 0; i-- {
		resp, err = r.exchange(m)
		if err == nil {
			return
		}
		time.Sleep(r.RetryWait)
	}
	return
}
