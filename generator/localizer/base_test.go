package localizer_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/generator/localizer"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func runLocalizerTest(t *testing.T, host string, qtype uint16, remoteIP net.IP, expected dns.RR) {
	handler := localizer.New()
	assert.NoError(t, handler.AddRecord("example.com", "0.0.1.2/16"))
	assert.NoError(t, handler.AddRecord("example.com", "fe80::1/64"))
	assert.NoError(t, handler.AddRecord("v4.example.com", "0.0.1.2/16"))
	assert.NoError(t, handler.AddRecord("v6.example.com", "fe80::1/64"))

	wr := &generator.TestResponseWriter{
		RemoteAddrVal: &net.TCPAddr{
			IP:   remoteIP,
			Port: 5053,
		},
	}
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
			util.FillHeader(expected, host, qtype, 60),
		}, rr)
	}
}

func TestAFromIPv4(t *testing.T) {
	runLocalizerTest(t, "example.com.", dns.TypeA, net.IPv4(10, 99, 3, 4).To4(), &dns.A{
		A: net.IPv4(10, 99, 1, 2).To4(),
	})
}

func TestAFromIPv6(t *testing.T) {
	runLocalizerTest(t, "example.com.", dns.TypeA, net.IPv6loopback, nil)
}

func TestAAAAFromIPv4(t *testing.T) {
	runLocalizerTest(t, "example.com.", dns.TypeAAAA, net.IPv4(10, 99, 3, 4).To4(), nil)
}

func TestAAAAFromIPv6(t *testing.T) {
	runLocalizerTest(t, "example.com.", dns.TypeAAAA, net.ParseIP("fd00:abcd::1234:1"), &dns.AAAA{
		AAAA: net.ParseIP("fd00:abcd::1"),
	})
}
