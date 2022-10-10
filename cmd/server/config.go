package main

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type RDNSConfig struct {
	Enabled bool
	Suffix  string   `yaml:"suffix"`
	Subnets []string `yaml:"subnets"`
}

type Config struct {
	Global struct {
		NameServers []string `yaml:"nameservers"`
		Mailbox     string   `yaml:"mailbox"`
		Listen      string   `yaml:"listen"`
	} `yaml:"global"`

	RDNS struct {
		IPv4 RDNSConfig `yaml:"ipv4"`
		IPv6 RDNSConfig `yaml:"ipv6"`
	} `yaml:"rdns"`

	Resolver struct {
		Enabled     bool     `yaml:"enabled"`
		NameServers []string `yaml:"nameservers"`

		ServerName string `yaml:"server-name"`

		MaxConnections int           `yaml:"max-connections"`
		Retries        int           `yaml:"retries"`
		RetryWait      time.Duration `yaml:"retry-wait"`
		Timeout        time.Duration `yaml:"timeout"`

		AllowOnlyFromPrivate bool `yaml:"allow-only-from-private"`
	} `yaml:"resolver"`
}

func LoadConfig(file string) *Config {
	config := new(Config)
	config.Resolver.AllowOnlyFromPrivate = true // Safety!

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
