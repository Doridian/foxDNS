package main

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Global struct {
		NameServers []string `yaml:"nameservers"`
		Mailbox     string   `yaml:"mailbox"`
		Listen      []string `yaml:"listen"`
	} `yaml:"global"`

	RDNS []struct {
		IPVersion int      `yaml:"ip_version"`
		Suffix    string   `yaml:"suffix"`
		Subnets   []string `yaml:"subnets"`
	} `yaml:"rdns"`

	Resolvers []struct {
		Zone        string   `yaml:"zone"`
		NameServers []string `yaml:"nameservers"`
		Proto       string   `yaml:"proto"`

		ServerName string `yaml:"server-name"`

		MaxConnections int           `yaml:"max-connections"`
		Retries        int           `yaml:"retries"`
		RetryWait      time.Duration `yaml:"retry-wait"`
		Timeout        time.Duration `yaml:"timeout"`
		CacheSize      int           `yaml:"cache-size"`

		AllowOnlyFromPrivate bool `yaml:"allow-only-from-private"`
	} `yaml:"resolvers"`

	Localizers map[string][]string `yaml:"localizers"`

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
