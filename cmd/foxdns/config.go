package main

import (
	"os"
	"time"

	"github.com/Doridian/foxDNS/generator/authority"
	"github.com/Doridian/foxDNS/generator/localizer"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Global struct {
		Listen           []string              `yaml:"listen"`
		PrometheusListen string                `yaml:"prometheus-listen"`
		AuthorityConfig  *authority.AuthConfig `yaml:"authority-config"`
		UDPSize          int                   `yaml:"udp-size"`
	} `yaml:"global"`

	RDNS []struct {
		IPVersion           int                              `yaml:"ip_version"`
		Suffix              string                           `yaml:"suffix"`
		Subnets             []string                         `yaml:"subnets"`
		PTRAuthorityConfigs map[string]*authority.AuthConfig `yaml:"ptr-authority-configs"`
		AddrAuthorityConfig *authority.AuthConfig            `yaml:"addr-authority-config"`
		AddressTtl          time.Duration                    `yaml:"address-ttl"`
		PtrTtl              time.Duration                    `yaml:"ptr-ttl"`
	} `yaml:"rdns"`

	Resolvers []struct {
		Zone        string `yaml:"zone"`
		NameServers []struct {
			Addr               string        `yaml:"addr"`
			Proto              string        `yaml:"proto"`
			ServerName         string        `yaml:"server-name"`
			RequireCookie      bool          `yaml:"require-cookie"`
			MaxParallelQueries int           `yaml:"max-parallel-queries"`
			Timeout            time.Duration `yaml:"timeout"`
		} `yaml:"nameservers"`
		NameServerStrategy string `yaml:"nameserver-strategy"`

		MaxIdleTime   time.Duration `yaml:"max-idle-time"`
		Attempts      int           `yaml:"attempts"`
		RetryWait     time.Duration `yaml:"retry-wait"`
		LogFailures   bool          `yaml:"log-failures"`
		RequireCookie bool          `yaml:"require-cookie"`

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

		AllowOnlyFromPrivate bool `yaml:"allow-only-from-private"`
	} `yaml:"resolvers"`

	Localizers []struct {
		Zone            string                       `yaml:"zone"`
		Subnets         []string                     `yaml:"subnets"`
		Ttl             time.Duration                `yaml:"ttl"`
		AuthorityConfig *authority.AuthConfig        `yaml:"authority-config"`
		Rewrites        []localizer.LocalizerRewrite `yaml:"rewrites"`
	} `yaml:"localizers"`

	StaticZones []struct {
		Zone                  string                `yaml:"zone"`
		File                  string                `yaml:"file"`
		ResolveExternalCNAMES bool                  `yaml:"resolve-external-cnames"`
		RequireCookie         bool                  `yaml:"require-cookie"`
		AuthorityConfig       *authority.AuthConfig `yaml:"authority-config"`
	} `yaml:"static-zones"`

	AdLists struct {
		Urls            []string      `yaml:"urls"`
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
