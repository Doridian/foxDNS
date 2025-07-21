package handler

import (
	"os"

	"github.com/miekg/dns"
)

type DNSSECConfig struct {
	Zone string `yaml:"zone"`

	PublicZSKFile   string `yaml:"public-zsk"`
	PrivateZSKFile  string `yaml:"private-zsk"`
	PublicKSKFile   string `yaml:"public-ksk"`
	PrivateKSKFile  string `yaml:"private-ksk"`
	CacheSignatures bool   `yaml:"cache-signatures"`
}

func (h *Handler) loadDNSSEC(config *DNSSECConfig, zone string) {
	if config == nil {
		return
	}

	if !h.authoritative {
		panic("DNSSEC configuration can only be loaded for authoritative handlers")
	}

	if config.Zone != "" {
		h.zone = config.Zone
	} else {
		h.zone = zone
	}

	if h.zone == "" {
		panic("DNSSEC zone must be set")
	}

	h.zone = dns.CanonicalName(h.zone)

	h.signatures = make(map[string]*dns.RRSIG)
	h.enableSignatureCache = true

	if config.PublicZSKFile != "" {
		// Load ZSK
		fh, err := os.Open(config.PublicZSKFile)
		if err != nil {
			panic(err)
		}
		pubkey, err := dns.ReadRR(fh, config.PublicZSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		h.zskDNSKEY = pubkey.(*dns.DNSKEY)

		fh, err = os.Open(config.PrivateZSKFile)
		if err != nil {
			panic(err)
		}
		h.zskPrivateKey, err = h.zskDNSKEY.ReadPrivateKey(fh, config.PrivateZSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		// Load KSK
		fh, err = os.Open(config.PublicKSKFile)
		if err != nil {
			panic(err)
		}
		pubkey, err = dns.ReadRR(fh, config.PublicKSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		h.kskDNSKEY = pubkey.(*dns.DNSKEY)

		fh, err = os.Open(config.PrivateKSKFile)
		if err != nil {
			panic(err)
		}
		h.kskPrivateKey, err = h.kskDNSKEY.ReadPrivateKey(fh, config.PrivateKSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}
	}

	h.enableSignatureCache = config.CacheSignatures
}
