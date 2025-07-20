package main

import (
	"os"
	"time"

	"github.com/Doridian/foxDNS/handler/generator"
	"github.com/Doridian/foxDNS/handler/generator/localizer"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// Free form field for YAML inheritance usage
	Templates interface{} `yaml:"templates"`

	Global struct {
		Listen            []string          `yaml:"listen"`
		PrometheusListen  string            `yaml:"prometheus-listen"`
		Config            *generator.Config `yaml:"config"`
		UDPSize           int               `yaml:"udp-size"`
		MaxRecursionDepth int               `yaml:"max-recursion-depth"`
	} `yaml:"global"`

	RDNS []struct {
		IPVersion  int                          `yaml:"ip_version"`
		Suffix     string                       `yaml:"suffix"`
		Subnets    []string                     `yaml:"subnets"`
		PTRConfigs map[string]*generator.Config `yaml:"ptr-configs"`
		AddrConfig *generator.Config            `yaml:"addr-config"`
		AddressTtl time.Duration                `yaml:"address-ttl"`
		PtrTtl     time.Duration                `yaml:"ptr-ttl"`
	} `yaml:"rdns"`

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

	Localizers struct {
		Rewrites []localizer.LocalizerRewrite `yaml:"rewrites"`
		V4V6s    []localizer.V4V6Rewrite      `yaml:"v4v6s"`
		Zones    []struct {
			Zone     string                       `yaml:"zone"`
			Subnets  []string                     `yaml:"subnets"`
			Ttl      time.Duration                `yaml:"ttl"`
			Config   *generator.Config            `yaml:"config"`
			Rewrites []localizer.LocalizerRewrite `yaml:"rewrites"`
			V4V6s    []localizer.V4V6Rewrite      `yaml:"v4v6s"`
		} `yaml:"zones"`
	} `yaml:"localizers"`

	StaticZones []struct {
		Zone   string            `yaml:"zone"`
		File   string            `yaml:"file"`
		Config *generator.Config `yaml:"config"`
	} `yaml:"static-zones"`

	AdLists struct {
		AllowLists      []string          `yaml:"allow-lists"`
		BlockLists      []string          `yaml:"block-lists"`
		RefreshInterval time.Duration     `yaml:"refresh-interval"`
		Config          *generator.Config `yaml:"config"`
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
