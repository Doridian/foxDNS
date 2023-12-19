package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/generator/authority"
	"github.com/Doridian/foxDNS/generator/localizer"
	"github.com/Doridian/foxDNS/generator/rdns"
	"github.com/Doridian/foxDNS/generator/resolver"
	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/generator/static"
	"github.com/Doridian/foxDNS/server"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var generators = make([]generator.Generator, 0)
var configFile string
var srv *server.Server

func reloadConfig() {
	for _, gen := range generators {
		err := gen.Stop()
		if err != nil {
			log.Panicf("Error stopping generator: %v", err)
		}
	}

	config := LoadConfig(configFile)

	generators = make([]generator.Generator, 0)
	mux := dns.NewServeMux()

	for _, rdnsConf := range config.RDNS {
		rdnsGen := rdns.NewRDNSGenerator(rdnsConf.IPVersion)
		generators = append(generators, rdnsGen)

		if rdnsGen == nil {
			log.Panicf("Unknown IP version: %d", rdnsConf.IPVersion)
		}
		rdnsGen.PTRSuffix = rdnsConf.Suffix

		rdnsAuthMain := authority.NewAuthorityHandler(rdnsConf.Suffix, config.Global.NameServers, config.Global.Mailbox)
		rdnsAuthMain.Child = rdnsGen
		generators = append(generators, rdnsAuthMain)
		rdnsAuthMain.Register(mux)

		for _, subnet := range rdnsConf.Subnets {
			rdnsAuthSub := authority.NewAuthorityHandler(subnet, config.Global.NameServers, config.Global.Mailbox)
			rdnsAuthSub.Child = rdnsGen
			generators = append(generators, rdnsAuthSub)
			rdnsAuthSub.Register(mux)
		}
	}

	for _, resolvConf := range config.Resolvers {
		nameServers := make([]*resolver.ServerConfig, len(resolvConf.NameServers))
		for i, ns := range resolvConf.NameServers {
			nameServers[i] = &resolver.ServerConfig{
				Addr:       ns.Addr,
				Proto:      ns.Proto,
				ServerName: ns.ServerName,
			}
		}

		resolv := resolver.New(nameServers)
		generators = append(generators, resolv)

		resolv.AllowOnlyFromPrivate = resolvConf.AllowOnlyFromPrivate

		if resolvConf.MaxConnections > 0 {
			resolv.MaxConnections = resolvConf.MaxConnections
		}

		if resolvConf.MaxIdleTime > 0 {
			resolv.MaxIdleTime = resolvConf.MaxIdleTime
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

		if resolvConf.CacheSize > 0 {
			resolv.SetCacheSize(resolvConf.CacheSize)
		}

		if resolvConf.CacheMaxTime > 0 {
			resolv.CacheMaxTTL = int(resolvConf.CacheMaxTime.Seconds())
		}

		if resolvConf.CacheMinTime > 0 {
			resolv.CacheMinTTL = int(resolvConf.CacheMinTime.Seconds())
		}

		if resolvConf.CacheNoReplyTime > 0 {
			resolv.CacheNoReplyTTL = int(resolvConf.CacheNoReplyTime.Seconds())
		}

		if resolvConf.RecordMinTTL > 0 {
			resolv.RecordMinTTL = uint32(resolvConf.RecordMinTTL.Seconds())
		}

		if resolvConf.RecordMaxTTL > 0 {
			resolv.RecordMaxTTL = uint32(resolvConf.RecordMaxTTL.Seconds())
		}

		mux.Handle(resolvConf.Zone, resolv)

		log.Printf("Resolver enabled for zone %s (only private clients: %v)", resolvConf.Zone, resolv.AllowOnlyFromPrivate)
	}

	if len(config.Localizers) > 0 {
		for locName, locIPs := range config.Localizers {
			loc := localizer.New()
			generators = append(generators, loc)

			for _, ip := range locIPs {
				loc.AddRecord(locName, ip)
			}

			locAuth := authority.NewAuthorityHandler(locName, config.Global.NameServers, config.Global.Mailbox)
			locAuth.Child = loc
			locAuth.Register(mux)
		}

		log.Printf("Localizer enabled for %d zones", len(config.Localizers))
	}

	if len(config.StaticZones) > 0 {
		for statName, statFile := range config.StaticZones {
			stat := static.New()
			generators = append(generators, stat)
			err := stat.LoadZoneFile(statFile, statName, 3600, false)
			if err != nil {
				log.Printf("Error loading static zone %s: %v", statName, err)
			}

			statAuth := simple.New(statName)
			generators = append(generators, statAuth)
			statAuth.Child = stat
			statAuth.Register(mux)
		}

		log.Printf("Static zones enabled for %d zones", len(config.StaticZones))
	}

	if config.Global.PrometheusListen != "" {
		promMux := server.NewPrometheusDNSHandler(mux)
		srv.SetHandler(promMux)
	} else {
		srv.SetHandler(mux)
	}

	for _, gen := range generators {
		err := gen.Start()
		if err != nil {
			log.Panicf("Error starting generator: %v", err)
		}
	}
}

func main() {
	configFile = "config.yml"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	log.Printf("foxDNS version %s", util.Version)

	config := LoadConfig(configFile)

	if config.Global.PrometheusListen != "" {
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(config.Global.PrometheusListen, nil)
	}

	srv = server.NewServer(config.Global.Listen)
	reloadConfig()
	handleSignals(srv)
	srv.Serve()
}
