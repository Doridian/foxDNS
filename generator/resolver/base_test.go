package resolver_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/generator/resolver"
	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/generator/static"
	"github.com/Doridian/foxDNS/server"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

const dummyZone = "$TTL 300\n@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 604800 300\n@ IN NS ns1.example.com.\n@ IN NS ns2.example.com.\n@ IN A 10.13.37.0"

var dummyServer *server.Server
var resolverGenerator *resolver.Generator
var simpleHandler *simple.Generator

func initTests() {
	if dummyServer != nil {
		resolverGenerator.FlushCache()
		return
	}

	dummyServer = server.NewServer([]string{"127.0.0.1:12053"}, false)

	staticHandler := static.New(false)
	err := staticHandler.LoadZone(bytes.NewReader([]byte(dummyZone)), "example.com.db", "example.com.", 300, false)
	if err != nil {
		panic(err)
	}
	simpleHandler = simple.New("example.com.")
	simpleHandler.Child = staticHandler

	dummyServer.SetHandler(simpleHandler)
	go dummyServer.Serve()
	resolverGenerator = resolver.New([]*resolver.ServerConfig{
		{
			Addr:  "127.0.0.1:12053",
			Proto: "udp",
		},
	})
	dummyServer.WaitReady()
	err = resolverGenerator.Start()
	if err != nil {
		panic(err)
	}
}

func queryResolver(t *testing.T, q dns.Question) *dns.Msg {
	initTests()

	testWriter := &generator.TestResponseWriter{}
	qmsg := &dns.Msg{
		Question: []dns.Question{q},
	}
	resolverGenerator.ServeDNS(testWriter, qmsg)

	assert.True(t, testWriter.HadWrites)

	return testWriter.LastMsg
}

func TestExistingRecord(t *testing.T) {
	response := queryResolver(t, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})

	assert.Equal(t, dns.RcodeSuccess, response.Rcode)
	assert.ElementsMatch(t, []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      300,
				Rdlength: 4,
			},
			A: net.ParseIP("10.13.37.0").To4(),
		},
	}, response.Answer)
	assert.ElementsMatch(t, []dns.RR{}, response.Ns)
}

func TestNonExistingRecord(t *testing.T) {
	response := queryResolver(t, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeMX,
		Qclass: dns.ClassINET,
	})

	assert.Equal(t, dns.RcodeSuccess, response.Rcode)
	assert.ElementsMatch(t, []dns.RR{}, response.Answer)
	assert.ElementsMatch(t, []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeSOA,
				Class:    dns.ClassINET,
				Ttl:      300,
				Rdlength: 61,
			},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minttl:  300,
		},
	}, response.Ns)
}

func TestNXDOMAIN(t *testing.T) {
	response := queryResolver(t, dns.Question{
		Name:   "nx.example.com.",
		Qtype:  dns.TypeMX,
		Qclass: dns.ClassINET,
	})

	assert.Equal(t, dns.RcodeNameError, response.Rcode)
	assert.ElementsMatch(t, []dns.RR{}, response.Answer)
	assert.ElementsMatch(t, []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeSOA,
				Class:    dns.ClassINET,
				Ttl:      300,
				Rdlength: 61,
			},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minttl:  300,
		},
	}, response.Ns)
}

func TestExistingRecordWithCache(t *testing.T) {
	testWriter := &generator.TestResponseWriter{}
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

	assert.True(t, testWriter.HadWrites)
	response := testWriter.LastMsg
	assert.Equal(t, dns.RcodeSuccess, response.Rcode)
	assert.ElementsMatch(t, []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      300,
				Rdlength: 4,
			},
			A: net.ParseIP("10.13.37.0").To4(),
		},
	}, response.Answer)
	assert.ElementsMatch(t, []dns.RR{}, response.Ns)

	// Shut down backend resolver to make sure cache is required
	dummyServer.SetHandler(nil)

	testWriter = &generator.TestResponseWriter{}
	resolverGenerator.ServeDNS(testWriter, qmsg)

	assert.True(t, testWriter.HadWrites)
	response = testWriter.LastMsg
	assert.Equal(t, dns.RcodeSuccess, response.Rcode)
	assert.ElementsMatch(t, []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      300,
				Rdlength: 4,
			},
			A: net.ParseIP("10.13.37.0").To4(),
		},
	}, response.Answer)
	assert.ElementsMatch(t, []dns.RR{}, response.Ns)

	// And re-add the backend for future tests
	dummyServer.SetHandler(simpleHandler)
}
