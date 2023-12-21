package main

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type YAMLAuthorityConfig struct {
	NameServers []string `yaml:"nameservers"`
	Mailbox     string   `yaml:"mailbox"`
	SOATtl      uint32   `yaml:"soa-ttl"`
	NSTtl       uint32   `yaml:"ns-ttl"`
	Serial      uint32   `yaml:"serial"`
	Refresh     uint32   `yaml:"refresh"`
	Retry       uint32   `yaml:"retry"`
	Expire      uint32   `yaml:"expire"`
	Minttl      uint32   `yaml:"minttl"`
}

type Config struct {
	Global struct {
		Listen           []string             `yaml:"listen"`
		PrometheusListen string               `yaml:"prometheus-listen"`
		AuthorityConfig  *YAMLAuthorityConfig `yaml:"authority-config"`
	} `yaml:"global"`

	RDNS []struct {
		IPVersion       int                  `yaml:"ip_version"`
		Suffix          string               `yaml:"suffix"`
		Subnets         []string             `yaml:"subnets"`
		AuthorityConfig *YAMLAuthorityConfig `yaml:"authority-config"`
		AddressTtl      uint32               `yaml:"address-ttl"`
		PtrTtl          uint32               `yaml:"ptr-ttl"`
	} `yaml:"rdns"`

	Resolvers []struct {
		Zone        string `yaml:"zone"`
		NameServers []struct {
			Addr       string `yaml:"addr"`
			Proto      string `yaml:"proto"`
			ServerName string `yaml:"server-name"`
		} `yaml:"nameservers"`

		ServerName string `yaml:"server-name"`

		MaxConnections int           `yaml:"max-connections"`
		MaxIdleTime    time.Duration `yaml:"max-idle-time"`
		Retries        int           `yaml:"retries"`
		RetryWait      time.Duration `yaml:"retry-wait"`
		Timeout        time.Duration `yaml:"timeout"`

		CacheSize        int           `yaml:"cache-size"`
		CacheMaxTime     time.Duration `yaml:"cache-max-time"`
		CacheMinTime     time.Duration `yaml:"cache-min-time"`
		CacheNoReplyTime time.Duration `yaml:"cache-no-reply-time"`

		RecordMinTTL uint32 `yaml:"record-min-ttl"`
		RecordMaxTTL uint32 `yaml:"record-max-ttl"`

		AllowOnlyFromPrivate bool `yaml:"allow-only-from-private"`
	} `yaml:"resolvers"`

	Localizers []struct {
		Zone            string               `yaml:"zone"`
		Subnets         []string             `yaml:"subnets"`
		Ttl             uint32               `yaml:"ttl"`
		AuthorityConfig *YAMLAuthorityConfig `yaml:"authority-config"`
	} `yaml:"localizers"`

	StaticZones map[string]string `yaml:"static-zones"`
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
