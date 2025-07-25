package main

import (
	"os"
	"time"

	"github.com/Doridian/foxDNS/handler/localizer"
	"github.com/Doridian/foxDNS/handler/static"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// Free form field for YAML inheritance usage
	Templates interface{} `yaml:"templates"`

	Global struct {
		Listen            []string `yaml:"listen"`
		PrometheusListen  string   `yaml:"prometheus-listen"`
		UDPSize           int      `yaml:"udp-size"`
		MaxRecursionDepth int      `yaml:"max-recursion-depth"`
		RequireCookie     bool     `yaml:"require-cookie"`
	} `yaml:"global"`

	Resolvers []struct {
		Zones       []string `yaml:"zones"`
		NameServers []struct {
			Addr               string        `yaml:"addr"`
			Proto              string        `yaml:"proto"`
			ServerName         string        `yaml:"server-name"`
			RequireCookie      bool          `yaml:"require-cookie"`
			MaxParallelQueries int           `yaml:"max-parallel-queries"`
			Timeout            time.Duration `yaml:"timeout"`
		} `yaml:"nameservers"`
		NameServerStrategy string `yaml:"nameserver-strategy"`

		MaxIdleTime time.Duration `yaml:"max-idle-time"`
		Attempts    int           `yaml:"attempts"`
		RetryWait   time.Duration `yaml:"retry-wait"`
		LogFailures bool          `yaml:"log-failures"`

		CacheSize                 int           `yaml:"cache-size"`
		CacheMaxTime              time.Duration `yaml:"cache-max-time"`
		CacheMinTime              time.Duration `yaml:"cache-min-time"`
		CacheNoReplyTime          time.Duration `yaml:"cache-no-reply-time"`
		CacheStaleEntryKeepPeriod time.Duration `yaml:"cache-stale-entry-keep-period"`
		CacheReturnStalePeriod    time.Duration `yaml:"cache-return-stale-period"`

		OpportunisticCacheMinHits    int           `yaml:"opportunistic-cache-min-hits"`
		OpportunisticCacheMaxTimeLef time.Duration `yaml:"opportunistic-cache-max-time-left"`

		RecordMinTTL time.Duration `yaml:"record-min-ttl"`
		RecordMaxTTL time.Duration `yaml:"record-max-ttl"`
	} `yaml:"resolvers"`

	StaticZones []struct {
		Zone   string               `yaml:"zone"`
		Files  []string             `yaml:"files"`
		DNSSEC *static.DNSSECConfig `yaml:"dnssec"`

		Localizers struct {
			Rewrites []localizer.LocalizerRewrite `yaml:"rewrites"`
			V4V6s    []localizer.V4V6Rewrite      `yaml:"v4v6s"`
			Hosts    []struct {
				Host     string                       `yaml:"host"`
				Subnets  []string                     `yaml:"subnets"`
				Ttl      time.Duration                `yaml:"ttl"`
				Rewrites []localizer.LocalizerRewrite `yaml:"rewrites"`
				V4V6s    []localizer.V4V6Rewrite      `yaml:"v4v6s"`
			} `yaml:"hosts"`
		} `yaml:"localizers"`
	} `yaml:"static-zones"`

	AdLists struct {
		AllowLists      []string      `yaml:"allow-lists"`
		BlockLists      []string      `yaml:"block-lists"`
		RefreshInterval time.Duration `yaml:"refresh-interval"`
	} `yaml:"ad-lists"`
}

func LoadConfig(file string) *Config {
	config := new(Config)

	fh, err := os.Open(file)
	if err != nil {
		panic(err)
	}

	dec := yaml.NewDecoder(fh)
	dec.KnownFields(true)
	err = dec.Decode(config)
	if err != nil {
		panic(err)
	}

	return config
}
