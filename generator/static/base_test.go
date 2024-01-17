package static_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/generator/static"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func runStaticTest(t *testing.T, handler simple.Handler, q *dns.Question) (rr []dns.RR, nxdomain bool) {
	wr := &generator.TestResponseWriter{}
	rr, nxdomain = handler.HandleQuestion(q, wr)
	assert.False(t, wr.HadWrites)
	return
}

func TestBasicZone(t *testing.T) {
	handler := static.New(false, nil)

	recA := &dns.A{
		A: net.IPv4(127, 0, 0, 1),
	}
	util.FillHeader(recA, "example.com.", dns.TypeA, 60)
	handler.AddRecord(recA)

	recTXT := &dns.TXT{
		Txt: []string{"Hello World"},
	}
	util.FillHeader(recTXT, "example.com.", dns.TypeTXT, 60)
	handler.AddRecord(recTXT)

	recA2_1 := &dns.A{
		A: net.IPv4(127, 0, 0, 1),
	}
	util.FillHeader(recA2_1, "a2.example.com.", dns.TypeA, 60)
	handler.AddRecord(recA2_1)
	recA2_2 := &dns.A{
		A: net.IPv4(127, 0, 0, 2),
	}
	util.FillHeader(recA2_2, "a2.example.com.", dns.TypeA, 60)
	handler.AddRecord(recA2_2)

	recCNAME := &dns.CNAME{
		Target: "example.com.",
	}
	util.FillHeader(recCNAME, "cname.example.com.", dns.TypeCNAME, 60)
	handler.AddRecord(recCNAME)

	rr, nxdomain := runStaticTest(t, handler, &dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.False(t, nxdomain)
	assert.ElementsMatch(t, []dns.RR{recA}, rr)

	// Correctly gives NXDOMAIN
	rr, nxdomain = runStaticTest(t, handler, &dns.Question{
		Name:   "test.example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.True(t, nxdomain)
	assert.ElementsMatch(t, []dns.RR{}, rr)

	// Does not return types not asked for and no NXDOMAIN
	rr, nxdomain = runStaticTest(t, handler, &dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	})
	assert.False(t, nxdomain)
	assert.ElementsMatch(t, []dns.RR{}, rr)

	// Only gives type asked for
	rr, nxdomain = runStaticTest(t, handler, &dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	})
	assert.False(t, nxdomain)
	assert.ElementsMatch(t, []dns.RR{recTXT}, rr)

	// Multiple records
	rr, nxdomain = runStaticTest(t, handler, &dns.Question{
		Name:   "a2.example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.False(t, nxdomain)
	assert.ElementsMatch(t, []dns.RR{recA2_1, recA2_2}, rr)

	// Resolves local CNAMEs
	rr, nxdomain = runStaticTest(t, handler, &dns.Question{
		Name:   "cname.example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.False(t, nxdomain)
	assert.ElementsMatch(t, []dns.RR{recCNAME, recA}, rr)
}

func TestRejectsNonINET(t *testing.T) {
	handler := static.New(false, nil)

	recA := &dns.A{
		A: net.IPv4(127, 0, 0, 1),
	}
	util.FillHeader(recA, "example.com.", dns.TypeA, 60)
	recA.Hdr.Class = dns.ClassCHAOS
	handler.AddRecord(recA)

	rr, _ := runStaticTest(t, handler, &dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.ElementsMatch(t, []dns.RR{}, rr)
}

type dummyDNSHandler struct {
	msg    *dns.Msg
	answer []dns.RR
}

func (r *dummyDNSHandler) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	r.msg = msg
	_ = wr.WriteMsg(&dns.Msg{
		Answer: r.answer,
	})
}

func TestCallsCNAMEResolver(t *testing.T) {
	recA := &dns.A{
		A: net.IPv4(127, 0, 0, 1),
	}
	util.FillHeader(recA, "example.net.", dns.TypeA, 60)

	upstreamHandler := &dummyDNSHandler{
		answer: []dns.RR{recA},
	}
	handler := static.New(false, upstreamHandler)

	recCNAME := &dns.CNAME{
		Target: "example.net.",
	}
	util.FillHeader(recCNAME, "cname.example.com.", dns.TypeCNAME, 60)
	handler.AddRecord(recCNAME)

	// Resolves external CNAMEs
	rr, nxdomain := runStaticTest(t, handler, &dns.Question{
		Name:   "cname.example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.False(t, nxdomain)
	assert.ElementsMatch(t, []dns.RR{recCNAME, recA}, rr)

	assert.NotNil(t, upstreamHandler.msg)
	if upstreamHandler.msg == nil {
		return
	}
	assert.ElementsMatch(t, []dns.Question{
		{
			Name:   "example.net.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	}, upstreamHandler.msg.Question)
}

func TestDoesntCrashOnCallingNilCNAMEResolver(t *testing.T) {
	recA := &dns.A{
		A: net.IPv4(127, 0, 0, 1),
	}
	util.FillHeader(recA, "example.net.", dns.TypeA, 60)

	handler := static.New(false, nil)

	recCNAME := &dns.CNAME{
		Target: "example.net.",
	}
	util.FillHeader(recCNAME, "cname.example.com.", dns.TypeCNAME, 60)
	handler.AddRecord(recCNAME)

	// Resolves external CNAMEs
	rr, nxdomain := runStaticTest(t, handler, &dns.Question{
		Name:   "cname.example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.False(t, nxdomain)
	assert.ElementsMatch(t, []dns.RR{recCNAME}, rr)
}
