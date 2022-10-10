package main

import (
	"log"

	"github.com/FoxDenHome/foxdns/authority"
	"github.com/FoxDenHome/foxdns/rdns"
	"github.com/FoxDenHome/foxdns/resolver"
	"github.com/FoxDenHome/foxdns/server"
)

func main() {
	config := LoadConfig("config.yml")
	srv := server.NewServer()

	for _, rdnsConf := range config.RDNS {
		rdnsAuth := authority.NewAuthorityHandler(append([]string{
			rdnsConf.Suffix,
		}, rdnsConf.Subnets...), config.Global.NameServers, config.Global.Mailbox)

		rdnsGen := rdns.NewRDNSGenerator(rdnsConf.IPVersion)
		if rdnsGen == nil {
			log.Panicf("Unknown IP version: %d", rdnsConf.IPVersion)
		}
		rdnsGen.PTRSuffix = rdnsConf.Suffix

		rdnsAuth.Child = rdnsGen

		rdnsAuth.Register(srv.Mux)
	}

	for _, resolvConf := range config.Resolvers {
		resolv := resolver.NewResolver(resolvConf.NameServers)
		resolv.Client.TLSConfig.ServerName = resolvConf.ServerName

		if len(resolvConf.Proto) > 0 {
			resolv.Client.Net = resolvConf.Proto
		}

		resolv.AllowOnlyFromPrivate = resolvConf.AllowOnlyFromPrivate

		if resolvConf.MaxConnections > 0 {
			resolv.MaxConnections = resolvConf.MaxConnections
		}

		if resolvConf.Retries > 0 {
			resolv.Retries = resolvConf.Retries
		}

		if resolvConf.RetryWait > 0 {
			resolv.RetryWait = resolvConf.RetryWait
		}

		if resolvConf.Timeout > 0 {
			resolv.SetTimeout(resolvConf.Timeout)
		}

		srv.Mux.Handle(resolvConf.Zone, resolv)

		log.Printf("Resolver enabled for zone %s (only private clients: %v)", resolvConf.Zone, resolv.AllowOnlyFromPrivate)
	}

	if len(config.Global.Listen) > 0 {
		srv.Listen = config.Global.Listen
	}

	srv.Serve()
}
