package static

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

func (r *Generator) loadDNSSEC(config *DNSSECConfig) {
	if config == nil {
		return
	}

	r.signatures = make(map[string]*dns.RRSIG)
	r.enableSignatureCache = config.CacheSignatures
	r.zone = config.Zone

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

		r.zskDNSKEY = pubkey.(*dns.DNSKEY)

		fh, err = os.Open(config.PrivateZSKFile)
		if err != nil {
			panic(err)
		}
		r.zskPrivateKey, err = r.zskDNSKEY.ReadPrivateKey(fh, config.PrivateZSKFile)
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

		r.kskDNSKEY = pubkey.(*dns.DNSKEY)

		fh, err = os.Open(config.PrivateKSKFile)
		if err != nil {
			panic(err)
		}
		r.kskPrivateKey, err = r.kskDNSKEY.ReadPrivateKey(fh, config.PrivateKSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}
	}
}
