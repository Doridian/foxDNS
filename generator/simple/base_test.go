package simple_test

import (
	"testing"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

type TestHandler struct {
	q        dns.Question
	recs     []dns.RR
	soaRecs  []dns.RR
	nxdomain bool
}

func (*TestHandler) GetName() string {
	return "test"
}

func (t *TestHandler) HandleQuestion(q dns.Question, wr dns.ResponseWriter) (recs []dns.RR, nxdomain bool) {
	if q.Qtype == dns.TypeSOA {
		return t.soaRecs, false
	}
	t.q = q
	return t.recs, t.nxdomain
}

func testQuestion(t *testing.T, handler *simple.Generator, q dns.Question, rr []dns.RR, soaRR []dns.RR, nxdomain bool) {
	wr := &generator.TestResponseWriter{}

	testHandler := &TestHandler{
		recs:     rr,
		soaRecs:  soaRR,
		nxdomain: nxdomain,
	}

	handler.Child = testHandler
	handler.ServeDNS(wr, &dns.Msg{
		Question: []dns.Question{q},
	})

	assert.NotNil(t, wr.LastMsg.IsEdns0())
	assert.True(t, wr.HadWrites)
	assert.ElementsMatch(t, wr.LastMsg.Question, []dns.Question{q})
	assert.ElementsMatch(t, wr.LastMsg.Answer, testHandler.recs)

	if len(wr.LastMsg.Answer) == 0 {
		assert.ElementsMatch(t, wr.LastMsg.Ns, testHandler.soaRecs)
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
	soaRecs := []dns.RR{
		util.FillHeader(&dns.SOA{
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 2,
			Retry:   3,
			Expire:  4,
			Minttl:  5,
		}, "example.com.", dns.TypeSOA, 60),
	}

	testQuestion(t, simple.New("example.com"), dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}, []dns.RR{}, soaRecs, false)

	testQuestion(t, simple.New("example.com"), dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}, []dns.RR{}, soaRecs, true)
}
