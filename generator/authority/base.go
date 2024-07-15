package authority

import (
	"crypto"
	"log"
	"os"
	"sync"
	"time"

	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type AuthConfig struct {
	Nameservers   []string      `yaml:"nameservers"`
	Mbox          string        `yaml:"mailbox"`
	SOATtl        time.Duration `yaml:"soa-ttl"`
	NSTtl         time.Duration `yaml:"ns-ttl"`
	Serial        uint32        `yaml:"serial"`
	Refresh       time.Duration `yaml:"refresh"`
	Retry         time.Duration `yaml:"retry"`
	Expire        time.Duration `yaml:"expire"`
	Minttl        time.Duration `yaml:"minttl"`
	RequireCookie bool          `yaml:"require-cookie"`
	ZoneName      *string       `yaml:"zone-name"`

	DNSSECPublicZSKFile   *string `yaml:"dnssec-public-zsk"`
	DNSSECPrivateZSKFile  *string `yaml:"dnssec-private-zsk"`
	DNSSECPublicKSKFile   *string `yaml:"dnssec-public-ksk"`
	DNSSECPrivateKSKFile  *string `yaml:"dnssec-private-ksk"`
	DNSSECSignerName      *string `yaml:"dnssec-signer-name"`
	DNSSECCacheSignatures *bool   `yaml:"dnssec-cache-signatures"`
}

type AuthorityHandler struct {
	soa         []dns.RR
	ns          []dns.RR
	zone        string
	handlerZone string

	enableSignatureCache bool
	signatureLock        sync.Mutex
	signatures           map[string]*dns.RRSIG
	signerName           string
	zskDNSKEY            *dns.DNSKEY
	zskPrivateKey        crypto.PrivateKey
	kskDNSKEY            *dns.DNSKEY
	kskPrivateKey        crypto.PrivateKey

	RequireCookie bool
	Child         simple.Handler
}

func GetDefaultAuthorityConfig() AuthConfig {
	return AuthConfig{
		SOATtl:  300,
		NSTtl:   300,
		Serial:  2022010169,
		Refresh: 43200,
		Retry:   3600,
		Expire:  86400,
		Minttl:  300,
	}
}

func FillAuthHeader(rr dns.RR, rtype uint16, zone string, ttl uint32) dns.RR {
	return util.FillHeader(rr, zone, rtype, ttl)
}

func NewAuthorityHandler(handlerZone string, config AuthConfig) *AuthorityHandler {
	hdl := &AuthorityHandler{
		signatures:           make(map[string]*dns.RRSIG),
		enableSignatureCache: true,
	}

	hdl.handlerZone = dns.CanonicalName(handlerZone)

	if config.ZoneName != nil {
		hdl.zone = *config.ZoneName
	}
	if hdl.zone == "" {
		hdl.zone = hdl.handlerZone
	} else {
		hdl.zone = dns.CanonicalName(hdl.zone)
	}

	hdl.RequireCookie = config.RequireCookie
	hdl.soa = make([]dns.RR, 0)
	hdl.ns = make([]dns.RR, 0)
	if hdl.zone == hdl.handlerZone {
		hdl.soa = []dns.RR{
			FillAuthHeader(&dns.SOA{
				Ns:      dns.CanonicalName(config.Nameservers[0]),
				Mbox:    dns.CanonicalName(config.Mbox),
				Serial:  config.Serial,
				Refresh: uint32(config.Refresh.Seconds()),
				Retry:   uint32(config.Retry.Seconds()),
				Expire:  uint32(config.Expire.Seconds()),
				Minttl:  uint32(config.Minttl.Seconds()),
			}, dns.TypeSOA, hdl.zone, uint32(config.SOATtl.Seconds())),
		}

		nsTtl := uint32(config.NSTtl.Seconds())
		for _, ns := range config.Nameservers {
			hdl.ns = append(hdl.ns, FillAuthHeader(&dns.NS{
				Ns: dns.CanonicalName(ns),
			}, dns.TypeNS, hdl.zone, nsTtl))
		}
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

		hdl.zskDNSKEY = pubkey.(*dns.DNSKEY)

		privateZSKFile := util.StringOrEmpty(config.DNSSECPrivateZSKFile)
		fh, err = os.Open(privateZSKFile)
		if err != nil {
			panic(err)
		}
		hdl.zskPrivateKey, err = hdl.zskDNSKEY.ReadPrivateKey(fh, privateZSKFile)
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

		hdl.kskDNSKEY = pubkey.(*dns.DNSKEY)

		privateKSKFile := util.StringOrEmpty(config.DNSSECPrivateKSKFile)
		fh, err = os.Open(privateKSKFile)
		if err != nil {
			panic(err)
		}
		hdl.kskPrivateKey, err = hdl.kskDNSKEY.ReadPrivateKey(fh, privateKSKFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}
	}

	if config.DNSSECCacheSignatures != nil {
		hdl.enableSignatureCache = *config.DNSSECCacheSignatures
	}

	hdl.signerName = ""
	if config.DNSSECSignerName != nil {
		signerName := *config.DNSSECSignerName
		if signerName != "" {
			hdl.signerName = dns.CanonicalName(signerName)
		}
	}
	if hdl.signerName == "" {
		hdl.signerName = hdl.zone
	}

	return hdl
}

func (r *AuthorityHandler) ServeDNS(wr dns.ResponseWriter, msg *dns.Msg) {
	reply := &dns.Msg{
		Compress: true,
		MsgHdr: dns.MsgHdr{
			Authoritative: true,
		},
	}
	reply.SetRcode(msg, dns.RcodeSuccess)

	ok, option := util.ApplyEDNS0ReplyEarly(msg, reply, wr, r.RequireCookie)
	if !ok {
		_ = wr.WriteMsg(reply)
		return
	}

	defer func() {
		util.ApplyEDNS0Reply(msg, reply, option, wr, r.RequireCookie)
		_ = wr.WriteMsg(reply)
	}()

	q := &msg.Question[0]
	if q.Qclass != dns.ClassINET {
		reply.Rcode = dns.RcodeRefused
		return
	}

	q.Name = dns.CanonicalName(q.Name)

	if q.Name == r.zone {
		switch q.Qtype {
		case dns.TypeSOA:
			reply.Answer = r.soa
		case dns.TypeNS:
			reply.Answer = r.ns
		case dns.TypeDNSKEY:
			if r.zskDNSKEY != nil && q.Name == r.signerName {
				reply.Answer = []dns.RR{r.zskDNSKEY, r.kskDNSKEY}
			}
		}
	}

	if r.Child != nil && len(reply.Answer) < 1 {
		var nxdomain bool
		reply.Answer, nxdomain = r.Child.HandleQuestion(q, wr)
		util.SetHandlerName(wr, r.Child)
		if nxdomain {
			reply.Rcode = dns.RcodeNameError
		}

		if len(reply.Answer) < 1 {
			reply.Ns = r.soa
		}
	} else {
		util.SetHandlerName(wr, r)
	}

	signer, err := r.signResponse(q, msg, reply.Answer)
	if err != nil {
		log.Printf("Error signing record for %s: %v", reply.Answer[0].Header().Name, err)
	} else if signer != nil {
		reply.Answer = append(reply.Answer, signer)
	}
}

func (r *AuthorityHandler) Register(mux *dns.ServeMux) {
	mux.Handle(r.handlerZone, r)
}

func (r *AuthorityHandler) Refresh() error {
	return nil
}

func (r *AuthorityHandler) Start() error {
	return nil
}

func (r *AuthorityHandler) Stop() error {
	return nil
}

func (r *AuthorityHandler) GetName() string {
	return "authority"
}
