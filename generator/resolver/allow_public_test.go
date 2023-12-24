package resolver_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestAllowOnlyPrivateFalseFromPublic(t *testing.T) {
	initTests()
	resolverGenerator.AllowOnlyFromPrivate = false

	testWriter := &generator.TestResponseWriter{
		RemoteAddrVal: &net.UDPAddr{
			IP:   net.ParseIP("8.8.8.8").To4(),
			Port: 12345,
		},
	}
	qmsg := &dns.Msg{
		Question: []dns.Question{
			{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}
	resolverGenerator.ServeDNS(testWriter, qmsg)

	assert.Equal(t, dns.RcodeSuccess, testWriter.LastMsg.Rcode)
	assert.ElementsMatch(t, []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      5,
				Rdlength: 4,
			},
			A: net.ParseIP("10.13.37.0").To4(),
		},
	}, testWriter.LastMsg.Answer)
	assert.ElementsMatch(t, []dns.RR{}, testWriter.LastMsg.Ns)
}

func TestAllowOnlyPrivateTrueFromPublic(t *testing.T) {
	initTests()
	resolverGenerator.AllowOnlyFromPrivate = true

	testWriter := &generator.TestResponseWriter{
		RemoteAddrVal: &net.UDPAddr{
			IP:   net.ParseIP("8.8.8.8").To4(),
			Port: 12345,
		},
	}
	qmsg := &dns.Msg{
		Question: []dns.Question{
			{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	resolverGenerator.ServeDNS(testWriter, qmsg)

	assert.Equal(t, dns.RcodeRefused, testWriter.LastMsg.Rcode)
	assert.Empty(t, testWriter.LastMsg.Answer)
	assert.Empty(t, testWriter.LastMsg.Ns)
}

func TestAllowOnlyPrivateTrueFromPrivate(t *testing.T) {
	initTests()
	resolverGenerator.AllowOnlyFromPrivate = true

	testWriter := &generator.TestResponseWriter{
		RemoteAddrVal: &net.UDPAddr{
			IP:   net.ParseIP("10.20.30.40").To4(),
			Port: 12345,
		},
	}
	qmsg := &dns.Msg{
		Question: []dns.Question{
			{
				Name:   "example.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	resolverGenerator.ServeDNS(testWriter, qmsg)

	assert.Equal(t, dns.RcodeSuccess, testWriter.LastMsg.Rcode)
	assert.ElementsMatch(t, []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      5,
				Rdlength: 4,
			},
			A: net.ParseIP("10.13.37.0").To4(),
		},
	}, testWriter.LastMsg.Answer)
	assert.ElementsMatch(t, []dns.RR{}, testWriter.LastMsg.Ns)
}
