package main

import (
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

	if config.DNSSECPublicZSKFile != nil {
		base.DNSSECPublicZSKFile = config.DNSSECPublicZSKFile
	}

	if config.DNSSECPrivateZSKFile != nil {
		base.DNSSECPrivateZSKFile = config.DNSSECPrivateZSKFile
	}

	if config.DNSSECPublicKSKFile != nil {
		base.DNSSECPublicKSKFile = config.DNSSECPublicKSKFile
	}

	if config.DNSSECPrivateKSKFile != nil {
		base.DNSSECPrivateKSKFile = config.DNSSECPrivateKSKFile
	}

	if config.DNSSECSignerName != nil {
		base.DNSSECSignerName = config.DNSSECSignerName
	}

	if config.DNSSECCacheSignatures != nil {
		base.DNSSECCacheSignatures = config.DNSSECCacheSignatures
	}

	if config.ZoneName != nil {
		base.ZoneName = config.ZoneName
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

		addrAuthConfig := mergeAuthorityConfig(rdnsConf.AddrAuthorityConfig, authorityConfig)
		addrZone := rdnsGen.GetAddrZone()
		rdnsAuth := authority.NewAuthorityHandler(addrZone, addrAuthConfig)
		rdnsAuth.Child = rdnsGen
		generators = append(generators, rdnsAuth)
		rdnsAuth.Register(mux)

		for zone, ptrAuthConfig := range rdnsConf.PTRAuthorityConfigs {
			rdnsConf.PTRAuthorityConfigs[dns.CanonicalName(zone)] = ptrAuthConfig
			rdnsConf.PTRAuthorityConfigs[strings.ToLower(zone)] = ptrAuthConfig
		}

		ptrAuthorityConfigBase := mergeAuthorityConfig(rdnsConf.PTRAuthorityConfigs["default"], authorityConfig)
		ptrZones := rdnsGen.GetPTRZones()
		for _, zone := range ptrZones {
			ptrAuthConfig := mergeAuthorityConfig(rdnsConf.PTRAuthorityConfigs[zone], ptrAuthorityConfigBase)
			rdnsAuth := authority.NewAuthorityHandler(zone, ptrAuthConfig)
			rdnsAuth.Child = rdnsGen
			generators = append(generators, rdnsAuth)
			rdnsAuth.Register(mux)
		}
	}

	for _, resolvConf := range config.Resolvers {
		nameServers := make([]*resolver.ServerConfig, len(resolvConf.NameServers))
		for i, ns := range resolvConf.NameServers {
			nameServers[i] = &resolver.ServerConfig{
				Addr:               ns.Addr,
				Proto:              ns.Proto,
				ServerName:         ns.ServerName,
				RequireCookie:      ns.RequireCookie,
				MaxParallelQueries: ns.MaxParallelQueries,
				Timeout:            ns.Timeout,
			}
		}

		resolv := resolver.New(nameServers)
		generators = append(generators, resolv)

		resolv.LogFailures = resolvConf.LogFailures

		if resolvConf.MaxIdleTime > 0 {
			resolv.MaxIdleTime = resolvConf.MaxIdleTime
		}

		if resolvConf.Attempts > 0 {
			resolv.Attempts = resolvConf.Attempts
		}

		if resolvConf.RetryWait > 0 {
			resolv.RetryWait = resolvConf.RetryWait
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

		if resolvConf.NameServerStrategy != "" {
			switch resolvConf.NameServerStrategy {
			case "round-robin":
				resolv.ServerStrategy = resolver.StrategyRoundRobin
			case "random":
				resolv.ServerStrategy = resolver.StrategyRandom
			case "failover":
				resolv.ServerStrategy = resolver.StrategyFailover
			default:
				log.Panicf("Unknown nameserver strategy: %s", resolvConf.NameServerStrategy)
			}
		}

		resolv.RequireCookie = resolvConf.RequireCookie

		for _, zone := range resolvConf.Zones {
			mux.Handle(zone, resolv)
		}

		log.Printf("Resolver enabled for zones %v", resolvConf.Zones)
	}

	if len(config.Localizers.Zones) > 0 {
		for _, locConfig := range config.Localizers.Zones {
			loc := localizer.New()

			if locConfig.Ttl > 0 {
				loc.Ttl = uint32(locConfig.Ttl.Seconds())
			}

			rewrites := config.Localizers.Rewrites
			if locConfig.Rewrites != nil {
				rewrites = locConfig.Rewrites
			}
			err := loc.AddRewrites(rewrites)
			if err != nil {
				log.Panicf("Error adding localizer rewrites: %v", err)
			}

			v4v6s := config.Localizers.V4V6s
			if locConfig.V4V6s != nil {
				v4v6s = locConfig.V4V6s
			}
			err = loc.AddV4V6s(v4v6s)
			if err != nil {
				log.Panicf("Error adding localizer v4v6s: %v", err)
			}

			generators = append(generators, loc)

			for _, ip := range locConfig.Subnets {
				err := loc.AddRecord(locConfig.Zone, ip)
				if err != nil {
					log.Panicf("Error adding localizer record %s -> %s: %v", locConfig.Zone, ip, err)
				}
			}

			locAuthConfig := mergeAuthorityConfig(locConfig.AuthorityConfig, authorityConfig)
			boolFalse := false
			locAuthConfig.DNSSECCacheSignatures = &boolFalse
			locAuth := authority.NewAuthorityHandler(locConfig.Zone, locAuthConfig)
			locAuth.Child = loc
			locAuth.Register(mux)
		}

		log.Printf("Localizer enabled for %d zones", len(config.Localizers.Zones))
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

			statAuthorityConfig := mergeAuthorityConfig(statConf.AuthorityConfig, authorityConfig)
			statAuth := authority.NewAuthorityHandler(statConf.Zone, statAuthorityConfig)
			statAuth.RequireCookie = statConf.RequireCookie
			generators = append(generators, statAuth)
			statAuth.Child = stat
			statAuth.Register(mux)
		}

		log.Printf("Static zones enabled for %d zones", len(config.StaticZones))
	}

	if len(config.AdLists.BlockLists) > 0 {
		adlistGen := blackhole.NewAdlist(config.AdLists.BlockLists, config.AdLists.AllowLists, mux, config.AdLists.RefreshInterval)
		generators = append(generators, adlistGen)
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
