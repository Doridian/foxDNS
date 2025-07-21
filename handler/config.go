package handler

import (
	"os"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	Nameservers []string      `yaml:"nameservers"`
	Mbox        string        `yaml:"mailbox"`
	SOATtl      time.Duration `yaml:"soa-ttl"`
	NSTtl       time.Duration `yaml:"ns-ttl"`
	Serial      uint32        `yaml:"serial"`
	Refresh     time.Duration `yaml:"refresh"`
	Retry       time.Duration `yaml:"retry"`
	Expire      time.Duration `yaml:"expire"`
	MinTtl      time.Duration `yaml:"min-ttl"`

	Zone string `yaml:"zone"`

	DNSSECPublicZSKFile   string `yaml:"dnssec-public-zsk"`
	DNSSECPrivateZSKFile  string `yaml:"dnssec-private-zsk"`
	DNSSECPublicKSKFile   string `yaml:"dnssec-public-ksk"`
	DNSSECPrivateKSKFile  string `yaml:"dnssec-private-ksk"`
	DNSSECCacheSignatures bool   `yaml:"dnssec-cache-signatures"`
}

func (h *Handler) loadConfig(config Config, zone string) {
	if !h.authoritative {
		return
	}

	if zone == "" {
		panic("Tried to use authoritative config for zoneless handler")
	}

	if config.Zone != "" {
		h.zone = config.Zone
	} else {
		h.zone = zone
	}

	h.zone = dns.CanonicalName(h.zone)

	h.signatures = make(map[string]*dns.RRSIG)
	h.enableSignatureCache = true

	h.soa = []dns.RR{
		FillAuthHeader(&dns.SOA{
			Ns:      dns.CanonicalName(config.Nameservers[0]),
			Mbox:    dns.CanonicalName(config.Mbox),
			Serial:  config.Serial,
			Refresh: uint32(config.Refresh.Seconds()),
			Retry:   uint32(config.Retry.Seconds()),
			Expire:  uint32(config.Expire.Seconds()),
			Minttl:  uint32(config.MinTtl.Seconds()),
		}, dns.TypeSOA, h.zone, uint32(config.SOATtl.Seconds())),
	}

	h.ns = make([]dns.RR, 0, len(config.Nameservers))
	nsTtl := uint32(config.NSTtl.Seconds())
	for _, ns := range config.Nameservers {
		h.ns = append(h.ns, FillAuthHeader(&dns.NS{
			Ns: dns.CanonicalName(ns),
		}, dns.TypeNS, h.zone, nsTtl))
	}

	if config.DNSSECPublicZSKFile != "" {
		// Load ZSK
		fh, err := os.Open(config.DNSSECPublicZSKFile)
		if err != nil {
			panic(err)
		}
		pubkey, err := dns.ReadRR(fh, config.DNSSECPublicZSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		h.zskDNSKEY = pubkey.(*dns.DNSKEY)

		fh, err = os.Open(config.DNSSECPrivateZSKFile)
		if err != nil {
			panic(err)
		}
		h.zskPrivateKey, err = h.zskDNSKEY.ReadPrivateKey(fh, config.DNSSECPrivateZSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		// Load KSK
		fh, err = os.Open(config.DNSSECPublicKSKFile)
		if err != nil {
			panic(err)
		}
		pubkey, err = dns.ReadRR(fh, config.DNSSECPublicKSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		h.kskDNSKEY = pubkey.(*dns.DNSKEY)

		fh, err = os.Open(config.DNSSECPrivateKSKFile)
		if err != nil {
			panic(err)
		}
		h.kskPrivateKey, err = h.kskDNSKEY.ReadPrivateKey(fh, config.DNSSECPrivateKSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}
	}

	h.enableSignatureCache = config.DNSSECCacheSignatures
}
