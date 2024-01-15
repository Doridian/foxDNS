package authority_test

import (
	"testing"
	"time"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/generator/authority"
	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

type TestHandler struct {
	q        *dns.Question
	recs     []dns.RR
	nxdomain bool
}

func (*TestHandler) GetName() string {
	return "test"
}

func (t *TestHandler) HandleQuestion(q *dns.Question, wr simple.DNSResponseWriter) (recs []dns.RR, nxdomain bool) {
	t.q = q
	return t.recs, t.nxdomain
}

func testQuestion(t *testing.T, handler *authority.AuthorityHandler, q dns.Question, rr []dns.RR, soaRR []dns.RR, nxdomain bool, edns0 bool) {
	wr := &generator.TestResponseWriter{}

	testHandler := &TestHandler{
		recs:     []dns.RR{},
		nxdomain: nxdomain,
	}

	qmsg := &dns.Msg{
		Question: []dns.Question{q},
	}
	if edns0 {
		qmsg.SetEdns0(util.UDPSize, false)
	}
	handler.Child = testHandler
	handler.ServeDNS(wr, qmsg)

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
	soaConfig := authority.AuthConfig{
		SOATtl:      300 * time.Second,
		NSTtl:       300 * time.Second,
		Mbox:        "hostmaster.example.com",
		Serial:      2022010169,
		Refresh:     43200 * time.Second,
		Retry:       3600 * time.Second,
		Expire:      86400 * time.Second,
		Minttl:      300 * time.Second,
		Nameservers: []string{"ns1.example.com", "ns2.example.com"},
	}
	handler := authority.NewAuthorityHandler("example.com", soaConfig)

	soaRecs := []dns.RR{
		authority.FillAuthHeader(&dns.SOA{
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  2022010169,
			Refresh: 43200,
			Retry:   3600,
			Expire:  86400,
			Minttl:  300,
		}, dns.TypeSOA, "example.com.", 300),
	}

	nsRecs := []dns.RR{
		authority.FillAuthHeader(&dns.NS{
			Ns: "ns1.example.com.",
		}, dns.TypeNS, "example.com.", 300),
		authority.FillAuthHeader(&dns.NS{
			Ns: "ns2.example.com.",
		}, dns.TypeNS, "example.com.", 300),
	}

	// We expect the SOA record to be returned
	testQuestion(t, handler, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}, []dns.RR{}, soaRecs, false, false)

	// We expect the SOA record to be returned and also EDNS0
	testQuestion(t, handler, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}, []dns.RR{}, soaRecs, false, true)

	// Ask explicitly for SOA, expect it to be returned
	testQuestion(t, handler, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeSOA,
		Qclass: dns.ClassINET,
	}, soaRecs, soaRecs, false, false)

	// We expect the NS record to be returned
	testQuestion(t, handler, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeNS,
		Qclass: dns.ClassINET,
	}, nsRecs, soaRecs, false, false)
}
