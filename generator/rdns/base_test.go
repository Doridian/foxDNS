package rdns_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/generator/rdns"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func runRDNSTest(t *testing.T, handler *rdns.Generator, host string, qtype uint16, expected dns.RR) {
	wr := &generator.TestResponseWriter{}
	rr, nxdomain := handler.HandleQuestion(&dns.Question{
		Name:   host,
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}, wr)
	assert.False(t, wr.HadWrites)
	assert.False(t, nxdomain)

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
