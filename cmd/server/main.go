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

	if config.RDNS.IPv4.Enabled {
		authv4 := authority.NewAuthorityHandler(append([]string{
			config.RDNS.IPv4.Suffix,
		}, config.RDNS.IPv4.Subnets...), config.Global.NameServers, config.Global.Mailbox)

		authv4.Child = &rdns.RDNSv4Generator{
			PTRSuffix: config.RDNS.IPv4.Suffix,
		}

		authv4.Register(srv.Mux)

		log.Printf("IPv4 Auto-rDNS enabled")
	} else {
		log.Printf("IPv4 Auto-rDNS disabled")
	}

	if config.RDNS.IPv6.Enabled {
		authv6 := authority.NewAuthorityHandler(append([]string{
			config.RDNS.IPv6.Suffix,
		}, config.RDNS.IPv6.Subnets...), config.Global.NameServers, config.Global.Mailbox)

		authv6.Child = &rdns.RDNSv6Generator{
			PTRSuffix: config.RDNS.IPv6.Suffix,
		}

		authv6.Register(srv.Mux)

		log.Printf("IPv6 Auto-rDNS enabled")
	} else {
		log.Printf("IPv6 Auto-rDNS disabled")
	}

	if config.Resolver.Enabled {
		resolv := resolver.NewResolver(config.Resolver.NameServers)
		resolv.Client.TLSConfig.ServerName = config.Resolver.ServerName

		resolv.AllowOnlyFromPrivate = config.Resolver.AllowOnlyFromPrivate

		if config.Resolver.MaxConnections > 0 {
			resolv.MaxConnections = config.Resolver.MaxConnections
		}

		if config.Resolver.Retries > 0 {
			resolv.Retries = config.Resolver.Retries
		}

		if config.Resolver.RetryWait > 0 {
			resolv.RetryWait = config.Resolver.RetryWait
		}

		if config.Resolver.Timeout > 0 {
			resolv.SetTimeout(config.Resolver.Timeout)
		}

		srv.Mux.Handle(".", resolv)

		log.Printf("Resolver enabled (only private clients: %v)", resolv.AllowOnlyFromPrivate)
	} else {
		log.Printf("Resolver disabled")
	}

	if len(config.Global.Listen) > 0 {
		srv.Listen = config.Global.Listen
	}

	srv.Serve()
}
