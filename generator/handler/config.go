package handler

import (
	"os"
	"time"

	"github.com/Doridian/foxDNS/util"
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
	Minttl      time.Duration `yaml:"minttl"`

	RequireCookie *bool `yaml:"require-cookie"`
	Authoritative *bool `yaml:"authoritative"`

	DNSSECPublicZSKFile   *string `yaml:"dnssec-public-zsk"`
	DNSSECPrivateZSKFile  *string `yaml:"dnssec-private-zsk"`
	DNSSECPublicKSKFile   *string `yaml:"dnssec-public-ksk"`
	DNSSECPrivateKSKFile  *string `yaml:"dnssec-private-ksk"`
	DNSSECSignerName      *string `yaml:"dnssec-signer-name"`
	DNSSECCacheSignatures *bool   `yaml:"dnssec-cache-signatures"`

	RecursionAvailable *bool `yaml:"recursion-available"`
}

func GetDefaultConfig() Config {
	boolTrue := true
	boolFalse := false

	return Config{
		SOATtl:  300,
		NSTtl:   300,
		Serial:  2022010169,
		Refresh: 43200,
		Retry:   3600,
		Expire:  86400,
		Minttl:  300,

		DNSSECCacheSignatures: &boolTrue,
		RequireCookie:         &boolFalse,
		RecursionAvailable:    &boolFalse,
	}
}

func (h *Handler) loadConfig(config Config) {
	h.soa = nil
	h.ns = nil
	h.recursionAvailable = config.RecursionAvailable != nil && *config.RecursionAvailable
	h.authoritative = config.Authoritative != nil && *config.Authoritative

	if !h.authoritative {
		return
	}

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
			Minttl:  uint32(config.Minttl.Seconds()),
		}, dns.TypeSOA, h.zone, uint32(config.SOATtl.Seconds())),
	}

	h.ns = make([]dns.RR, 0, len(config.Nameservers))
	nsTtl := uint32(config.NSTtl.Seconds())
	for _, ns := range config.Nameservers {
		h.ns = append(h.ns, FillAuthHeader(&dns.NS{
			Ns: dns.CanonicalName(ns),
		}, dns.TypeNS, h.zone, nsTtl))
	}

	publicZSKFile := util.StringOrEmpty(config.DNSSECPublicZSKFile)
	if publicZSKFile != "" {
		// Load ZSK
		fh, err := os.Open(publicZSKFile)
		if err != nil {
			panic(err)
		}
		pubkey, err := dns.ReadRR(fh, publicZSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		h.zskDNSKEY = pubkey.(*dns.DNSKEY)

		privateZSKFile := util.StringOrEmpty(config.DNSSECPrivateZSKFile)
		fh, err = os.Open(privateZSKFile)
		if err != nil {
			panic(err)
		}
		h.zskPrivateKey, err = h.zskDNSKEY.ReadPrivateKey(fh, privateZSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		// Load KSK
		publicKSKFile := util.StringOrEmpty(config.DNSSECPublicKSKFile)
		fh, err = os.Open(publicKSKFile)
		if err != nil {
			panic(err)
		}
		pubkey, err = dns.ReadRR(fh, publicKSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		h.kskDNSKEY = pubkey.(*dns.DNSKEY)

		privateKSKFile := util.StringOrEmpty(config.DNSSECPrivateKSKFile)
		fh, err = os.Open(privateKSKFile)
		if err != nil {
			panic(err)
		}
		h.kskPrivateKey, err = h.kskDNSKEY.ReadPrivateKey(fh, privateKSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}
	}

	if config.DNSSECCacheSignatures != nil {
		h.enableSignatureCache = *config.DNSSECCacheSignatures
	}

	h.signerName = ""
	if config.DNSSECSignerName != nil {
		signerName := *config.DNSSECSignerName
		if signerName != "" {
			h.signerName = dns.CanonicalName(signerName)
		}
	}

	if h.signerName == "" {
		h.signerName = h.zone
	}
}
