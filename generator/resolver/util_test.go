package resolver_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/generator/resolver"
	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/generator/static"
	"github.com/Doridian/foxDNS/server"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

const dummyZone = "$TTL 5\n@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 604800 300\n@ IN NS ns1.example.com.\n@ IN NS ns2.example.com.\n@ IN A 10.13.37.0"
const emptyZone = "$TTL 5\n@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 604800 300\n@ IN NS ns1.example.com.\n@ IN NS ns2.example.com."

var dummyServer *server.Server
var resolverGenerator *resolver.Generator
var simpleHandler *simple.Generator

func loadSimpleZone(zone string) *simple.Generator {
	staticHandler := static.New(false, nil)
	err := staticHandler.LoadZone(bytes.NewReader([]byte(zone)), "example.com.db", "example.com.", 300, false)
	if err != nil {
		panic(err)
	}
	staticHandler.Swap()

	simpleHandlerMake := simple.New("example.com.")
	simpleHandlerMake.Child = staticHandler
	return simpleHandlerMake
}

func initTests() {
	if dummyServer != nil {
		dummyServer.SetHandler(simpleHandler)
		resolverGenerator.FlushCache()
		resolverGenerator.AllowOnlyFromPrivate = false
		resolverGenerator.CurrentTime = time.Now
		return
	}

	dummyServer = server.NewServer([]string{"127.0.0.1:12053"}, false)

	simpleHandler = loadSimpleZone(dummyZone)

	dummyServer.SetHandler(simpleHandler)
	go dummyServer.Serve()
	resolverGenerator = resolver.New([]*resolver.ServerConfig{
		{
			Addr:  "127.0.0.1:12053",
			Proto: "udp",
		},
	})
	dummyServer.WaitReady()
	err := resolverGenerator.Start()
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
