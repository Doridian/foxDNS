package handler_test

import (
	"net"
	"testing"
	"time"

	"github.com/Doridian/foxDNS/handler"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

type TestHandler struct {
	q     *dns.Question
	recs  []dns.RR
	rcode int
}

func (*TestHandler) GetName() string {
	return "test"
}

func (t *TestHandler) Start() error {
	return nil
}

func (t *TestHandler) Stop() error {
	return nil
}

func (t *TestHandler) Refresh() error {
	return nil
}

func (t *TestHandler) HandleQuestion(q *dns.Question, _ bool, _ net.IP) (recs []dns.RR, ns []dns.RR, edns0Opts []dns.EDNS0, rcode int) {
	t.q = q
	return t.recs, nil, nil, t.rcode
}

func testQuestion(t *testing.T, zone string, config handler.Config, q dns.Question, rr []dns.RR, soaRR []dns.RR, nxdomain bool, edns0 bool) {
	wr := &handler.TestResponseWriter{}

	testHandler := &TestHandler{
		recs:  []dns.RR{},
		rcode: dns.RcodeSuccess,
	}
	if nxdomain {
		testHandler.rcode = dns.RcodeNameError
	}

	qmsg := &dns.Msg{
		Question: []dns.Question{q},
	}
	if edns0 {
		qmsg.SetEdns0(util.UDPSize, false)
	}
	hdl := handler.New(nil, testHandler, zone, config)
	hdl.ServeDNS(wr, qmsg)

	if edns0 {
		assert.NotNil(t, wr.LastMsg.IsEdns0())
	} else {
		assert.Nil(t, wr.LastMsg.IsEdns0())
	}
	assert.True(t, wr.HadWrites)
	assert.ElementsMatch(t, wr.LastMsg.Question, []dns.Question{q})
	assert.ElementsMatch(t, wr.LastMsg.Answer, rr)

	if len(rr) == 0 {
		assert.ElementsMatch(t, wr.LastMsg.Ns, soaRR)
	} else {
		assert.Empty(t, wr.LastMsg.Ns)
	}

	if nxdomain {
		assert.Equal(t, dns.RcodeNameError, wr.LastMsg.Rcode)
	} else {
		assert.Equal(t, dns.RcodeSuccess, wr.LastMsg.Rcode)
	}
}

func TestBasics(t *testing.T) {
	soaConfig := handler.Config{
		Authoritative: true,
		SOATtl:        300 * time.Second,
		NSTtl:         300 * time.Second,
		Mbox:          "hostmaster.example.com",
		Serial:        2022010169,
		Refresh:       43200 * time.Second,
		Retry:         3600 * time.Second,
		Expire:        86400 * time.Second,
		MinTtl:        300 * time.Second,
		Nameservers:   []string{"ns1.example.com", "ns2.example.com"},
	}
	zone := "example.com."

	soaRecs := []dns.RR{
		handler.FillAuthHeader(&dns.SOA{
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  2022010169,
			Refresh: 43200,
			Retry:   3600,
			Expire:  86400,
			Minttl:  300,
		}, dns.TypeSOA, zone, 300),
	}

	nsRecs := []dns.RR{
		handler.FillAuthHeader(&dns.NS{
			Ns: "ns1.example.com.",
		}, dns.TypeNS, zone, 300),
		handler.FillAuthHeader(&dns.NS{
			Ns: "ns2.example.com.",
		}, dns.TypeNS, zone, 300),
	}

	// We expect the SOA record to be returned
	testQuestion(t, zone, soaConfig, dns.Question{
		Name:   zone,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}, []dns.RR{}, soaRecs, false, false)

	// We expect the SOA record to be returned and also EDNS0
	testQuestion(t, zone, soaConfig, dns.Question{
		Name:   zone,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}, []dns.RR{}, soaRecs, false, true)

	// Ask explicitly for SOA, expect it to be returned
	testQuestion(t, zone, soaConfig, dns.Question{
		Name:   zone,
		Qtype:  dns.TypeSOA,
		Qclass: dns.ClassINET,
	}, soaRecs, soaRecs, false, false)

	// We expect the NS record to be returned
	testQuestion(t, zone, soaConfig, dns.Question{
		Name:   zone,
		Qtype:  dns.TypeNS,
		Qclass: dns.ClassINET,
	}, nsRecs, soaRecs, false, false)
}
