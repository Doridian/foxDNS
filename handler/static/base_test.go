package static_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/handler"
	"github.com/Doridian/foxDNS/handler/static"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func runStaticTest(handler handler.Generator, q *dns.Question) ([]dns.RR, []dns.RR, []dns.EDNS0, int) {
	return handler.HandleQuestion([]dns.Question{*q}, true, true, nil)
}

func TestBasicZone(t *testing.T) {
	handler := static.New(false, nil, nil)

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

	rr, _, _, rcode := runStaticTest(handler, &dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.Equal(t, dns.RcodeSuccess, rcode)
	assert.ElementsMatch(t, []dns.RR{recA}, rr)

	// Correctly gives NXDOMAIN
	rr, _, _, rcode = runStaticTest(handler, &dns.Question{
		Name:   "test.example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.Equal(t, dns.RcodeNameError, rcode)
	assert.ElementsMatch(t, []dns.RR{}, rr)

	// Does not return types not asked for and no NXDOMAIN
	rr, _, _, rcode = runStaticTest(handler, &dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	})
	assert.Equal(t, dns.RcodeSuccess, rcode)
	assert.ElementsMatch(t, []dns.RR{}, rr)

	// Only gives type asked for
	rr, _, _, rcode = runStaticTest(handler, &dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	})
	assert.Equal(t, dns.RcodeSuccess, rcode)
	assert.ElementsMatch(t, []dns.RR{recTXT}, rr)

	// Multiple records
	rr, _, _, rcode = runStaticTest(handler, &dns.Question{
		Name:   "a2.example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.Equal(t, dns.RcodeSuccess, rcode)
	assert.ElementsMatch(t, []dns.RR{recA2_1, recA2_2}, rr)

	// Resolves local CNAMEs
	rr, _, _, rcode = runStaticTest(handler, &dns.Question{
		Name:   "cname.example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	assert.Equal(t, dns.RcodeSuccess, rcode)
	assert.ElementsMatch(t, []dns.RR{recCNAME, recA}, rr)
}
