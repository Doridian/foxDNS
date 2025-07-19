package rdns_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/handler/generator/rdns"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func runRDNSTest(t *testing.T, handler *rdns.Generator, host string, qtype uint16, expected dns.RR) {
	rr, _, _, rcode := handler.HandleQuestion(&dns.Question{
		Name:   host,
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}, net.IPv4(127, 0, 0, 1))
	assert.Equal(t, dns.RcodeSuccess, rcode)

	if expected == nil {
		assert.Empty(t, rr)
	} else {
		assert.ElementsMatch(t, []dns.RR{
			util.FillHeader(expected, host, qtype, 3600),
		}, rr)
	}
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}
