package handler

import (
	"os"

	"github.com/miekg/dns"
)

type Config struct {
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
