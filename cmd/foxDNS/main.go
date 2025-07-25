package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Doridian/foxDNS/handler"
	"github.com/Doridian/foxDNS/handler/blackhole"
	"github.com/Doridian/foxDNS/handler/localizer"
	"github.com/Doridian/foxDNS/handler/resolver"
	"github.com/Doridian/foxDNS/handler/static"
	"github.com/Doridian/foxDNS/server"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var loaders = make([]handler.Loadable, 0)
var configFile string
var srv *server.Server
var enableFSNotify = os.Getenv("ENABLE_FSNOTIFY") != ""

func reloadConfig() {
	for _, gen := range loaders {
		err := gen.Stop()
		if err != nil {
			log.Panicf("Error stopping generator: %v", err)
		}
	}

	config := LoadConfig(configFile)

	if config.Global.UDPSize > 0 {
		util.UDPSize = uint16(config.Global.UDPSize)
	}
	if config.Global.MaxRecursionDepth > 0 {
		util.MaxRecursionDepth = config.Global.MaxRecursionDepth
	}
	util.RequireCookie = config.Global.RequireCookie

	loaders = make([]handler.Loadable, 0)
	mux := dns.NewServeMux()

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
		loaders = append(loaders, resolv)

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

		loaders = append(loaders, resolv)
		hdl := handler.New(resolv, false)
		for _, zone := range resolvConf.Zones {
			mux.Handle(zone, hdl)
		}

		log.Printf("Resolver enabled for zones %v", resolvConf.Zones)
	}

	if len(config.StaticZones) > 0 {
		for _, statConf := range config.StaticZones {
			stat := static.New(enableFSNotify, mux, statConf.DNSSEC)

			for _, file := range statConf.Files {
				err := stat.LoadZoneFile(file, statConf.Zone, 3600, false)
				if err != nil {
					log.Panicf("Error loading static zone file %s: %v", file, err)
				}
			}

			if len(statConf.Localizers.Hosts) > 0 {
				for _, locConfig := range statConf.Localizers.Hosts {
					loc := localizer.New()

					if locConfig.Ttl > 0 {
						loc.Ttl = uint32(locConfig.Ttl.Seconds())
					}

					rewrites := statConf.Localizers.Rewrites
					if locConfig.Rewrites != nil {
						rewrites = locConfig.Rewrites
					}
					err := loc.AddRewrites(rewrites)
					if err != nil {
						log.Panicf("Error adding localizer rewrites: %v", err)
					}

					v4v6s := statConf.Localizers.V4V6s
					if locConfig.V4V6s != nil {
						v4v6s = locConfig.V4V6s
					}
					err = loc.AddV4V6s(v4v6s)
					if err != nil {
						log.Panicf("Error adding localizer v4v6s: %v", err)
					}

					loaders = append(loaders, loc)

					for _, ip := range locConfig.Subnets {
						err := loc.AddRecord(locConfig.Host, ip)
						if err != nil {
							log.Panicf("Error adding localizer record %s -> %s: %v", locConfig.Host, ip, err)
						}
					}

					stat.AddSubHandler(locConfig.Host, loc)
				}

				log.Printf("Localizer enabled for %d hosts in %s zone", len(statConf.Localizers.Hosts), statConf.Zone)
			}

			loaders = append(loaders, stat)
			mux.Handle(statConf.Zone, handler.New(stat, true))
		}

		log.Printf("Static zones enabled for %d zones", len(config.StaticZones))
	}

	if len(config.AdLists.BlockLists) > 0 {
		adlistGen := blackhole.NewAdlist(config.AdLists.BlockLists, config.AdLists.AllowLists, mux, config.AdLists.RefreshInterval)
		loaders = append(loaders, adlistGen)
	}

	srv.SetHandler(mux)

	for _, gen := range loaders {
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
