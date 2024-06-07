package main

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/Doridian/foxDNS/generator"
	"github.com/Doridian/foxDNS/generator/authority"
	"github.com/Doridian/foxDNS/generator/blackhole"
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
var enableFSNotify = os.Getenv("ENABLE_FSNOTIFY") != ""

func mergeAuthorityConfig(config *authority.AuthConfig, base authority.AuthConfig) authority.AuthConfig {
	if config == nil {
		return base
	}

	if config.Nameservers != nil {
		base.Nameservers = config.Nameservers
	}

	if config.Mbox != "" {
		base.Mbox = config.Mbox
	}

	if config.SOATtl > 0 {
		base.SOATtl = config.SOATtl
	}

	if config.NSTtl > 0 {
		base.NSTtl = config.NSTtl
	}

	if config.Serial > 0 {
		base.Serial = config.Serial
	}

	if config.Refresh > 0 {
		base.Refresh = config.Refresh
	}

	if config.Retry > 0 {
		base.Retry = config.Retry
	}

	if config.Expire > 0 {
		base.Expire = config.Expire
	}

	if config.Minttl > 0 {
		base.Minttl = config.Minttl
	}

	if config.RequireCookie {
		base.RequireCookie = true
	}

	return base
}

func reloadConfig() {
	for _, gen := range generators {
		err := gen.Stop()
		if err != nil {
			log.Panicf("Error stopping generator: %v", err)
		}
	}

	config := LoadConfig(configFile)

	if config.Global.UDPSize > 0 {
		util.UDPSize = uint16(config.Global.UDPSize)
	}

	authorityConfig := mergeAuthorityConfig(config.Global.AuthorityConfig, authority.GetDefaultAuthorityConfig())

	generators = make([]generator.Generator, 0)
	mux := dns.NewServeMux()

	for _, rdnsConf := range config.RDNS {
		rdnsGen := rdns.NewRDNSGenerator(rdnsConf.IPVersion)
		generators = append(generators, rdnsGen)

		if rdnsGen == nil {
			log.Panicf("Unknown IP version: %d", rdnsConf.IPVersion)
		}
		rdnsGen.SetPTRSuffix(rdnsConf.Suffix)

		allowedSubnets := make([]*net.IPNet, 0, len(rdnsConf.Subnets))
		for _, subnet := range rdnsConf.Subnets {
			_, subnet, err := net.ParseCIDR(subnet)
			if err != nil {
				log.Panicf("Error parsing subnet %s: %v", subnet, err)
			}
			allowedSubnets = append(allowedSubnets, subnet)
		}
		rdnsGen.AllowedSubnets = allowedSubnets

		if rdnsConf.AddressTtl > 0 {
			rdnsGen.AddressTtl = uint32(rdnsConf.AddressTtl.Seconds())
		}

		if rdnsConf.PtrTtl > 0 {
			rdnsGen.PtrTtl = uint32(rdnsConf.PtrTtl.Seconds())
		}

		rdnsAuthorityConfig := mergeAuthorityConfig(rdnsConf.AuthorityConfig, authorityConfig)

		rdnsZones := rdnsGen.GetZones()
		for _, zone := range rdnsZones {
			rdnsAuth := authority.NewAuthorityHandler(zone, rdnsAuthorityConfig)
			rdnsAuth.Child = rdnsGen
			generators = append(generators, rdnsAuth)
			rdnsAuth.Register(mux)
		}
	}

	for _, resolvConf := range config.Resolvers {
		nameServers := make([]*resolver.ServerConfig, len(resolvConf.NameServers))
		for i, ns := range resolvConf.NameServers {
			nameServers[i] = &resolver.ServerConfig{
				Addr:          ns.Addr,
				Proto:         ns.Proto,
				ServerName:    ns.ServerName,
				RequireCookie: ns.RequireCookie,
			}
		}

		resolv := resolver.New(nameServers)
		generators = append(generators, resolv)

		resolv.AllowOnlyFromPrivate = resolvConf.AllowOnlyFromPrivate
		resolv.LogFailures = resolvConf.LogFailures

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

		if resolvConf.CacheStaleEntryKeepPeriod > 0 {
			resolv.CacheStaleEntryKeepPeriod = resolvConf.CacheStaleEntryKeepPeriod
		}

		if resolvConf.CacheReturnStalePeriod > 0 {
			resolv.CacheReturnStalePeriod = resolvConf.CacheReturnStalePeriod
		}

		if resolvConf.RecordMinTTL > 0 {
			resolv.RecordMinTTL = uint32(resolvConf.RecordMinTTL.Seconds())
		}

		if resolvConf.RecordMaxTTL > 0 {
			resolv.RecordMaxTTL = uint32(resolvConf.RecordMaxTTL.Seconds())
		}

		if resolvConf.OpportunisticCacheMinHits > 0 {
			resolv.OpportunisticCacheMinHits = uint64(resolvConf.OpportunisticCacheMinHits)
		}

		if resolvConf.OpportunisticCacheMaxTimeLef > 0 {
			resolv.OpportunisticCacheMaxTimeLeft = resolvConf.OpportunisticCacheMaxTimeLef
		}

		resolv.RequireCookie = resolvConf.RequireCookie

		mux.Handle(resolvConf.Zone, resolv)

		log.Printf("Resolver enabled for zone %s (only private clients: %v)", resolvConf.Zone, resolv.AllowOnlyFromPrivate)
	}

	if len(config.Localizers) > 0 {
		for _, locConfig := range config.Localizers {
			loc := localizer.New()

			if locConfig.Ttl > 0 {
				loc.Ttl = uint32(locConfig.Ttl.Seconds())
			}

			generators = append(generators, loc)

			for _, ip := range locConfig.Subnets {
				err := loc.AddRecord(locConfig.Zone, ip, locConfig.Rewrites)
				if err != nil {
					log.Panicf("Error adding localizer record %s -> %s: %v", locConfig.Zone, ip, err)
				}
			}

			locAuth := authority.NewAuthorityHandler(locConfig.Zone, mergeAuthorityConfig(locConfig.AuthorityConfig, authorityConfig))
			locAuth.Child = loc
			locAuth.Register(mux)
		}

		log.Printf("Localizer enabled for %d zones", len(config.Localizers))
	}

	if len(config.StaticZones) > 0 {
		for _, statConf := range config.StaticZones {
			var stat *static.Generator
			if statConf.ResolveExternalCNAMES {
				stat = static.New(enableFSNotify, mux)
			} else {
				stat = static.New(enableFSNotify, nil)
			}
			generators = append(generators, stat)
			err := stat.LoadZoneFile(statConf.File, statConf.Zone, 3600, false)
			if err != nil {
				log.Panicf("Error loading static zone %s: %v", statConf.Zone, err)
			}

			statAuth := simple.New(statConf.Zone)
			statAuth.RequireCookie = statConf.RequireCookie
			generators = append(generators, statAuth)
			statAuth.Child = stat
			statAuth.Register(mux)
		}

		log.Printf("Static zones enabled for %d zones", len(config.StaticZones))
	}

	if len(config.DomainBlockFiles) > 0 {
		blackholeGen := blackhole.New()
		for _, fileName := range config.DomainBlockFiles {
			file, err := os.Open(fileName)
			if err != nil {
				log.Panicf("Error opening domain block file %s: %v", fileName, err)
			}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				idx := strings.IndexRune(line, '#')
				if idx >= 0 {
					line = line[:idx]
				}
				line = strings.Trim(line, " \r\n\t")
				if line == "" {
					continue
				}
				mux.Handle(line, blackholeGen)
			}
			err = scanner.Err()
			if err != nil {
				log.Panicf("Error reading domain block file %s: %v", fileName, err)
			}
			_ = file.Close()
		}
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
		go func() {
			err := http.ListenAndServe(config.Global.PrometheusListen, nil)
			if err != nil {
				log.Panicf("Error starting Prometheus listener: %v", err)
			}
		}()
	}

	srv = server.NewServer(config.Global.Listen, true)
	reloadConfig()
	handleSignals(srv)
	srv.Serve()
}
