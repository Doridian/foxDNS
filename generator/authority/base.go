package authority

import (
	"crypto"
	"crypto/ecdsa"
	"log"
	"os"
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

	DNSSECPrivateKeyFile string `yaml:"dnssec-private-key"`
	DNSSECPublicKeyFile  string `yaml:"dnssec-public-key"`
}

type AuthorityHandler struct {
	soa              []dns.RR
	ns               []dns.RR
	zone             string
	dnssecDNSKEY     *dns.DNSKEY
	dnssecPrivateKey crypto.PrivateKey
	RequireCookie    bool
	Child            simple.Handler
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

func NewAuthorityHandler(zone string, config AuthConfig) *AuthorityHandler {
	hdl := &AuthorityHandler{}

	zone = dns.CanonicalName(zone)

	hdl.zone = zone
	hdl.RequireCookie = config.RequireCookie
	hdl.ns = make([]dns.RR, 0, len(config.Nameservers))
	hdl.soa = []dns.RR{
		FillAuthHeader(&dns.SOA{
			Ns:      dns.CanonicalName(config.Nameservers[0]),
			Mbox:    dns.CanonicalName(config.Mbox),
			Serial:  config.Serial,
			Refresh: uint32(config.Refresh.Seconds()),
			Retry:   uint32(config.Retry.Seconds()),
			Expire:  uint32(config.Expire.Seconds()),
			Minttl:  uint32(config.Minttl.Seconds()),
		}, dns.TypeSOA, zone, uint32(config.SOATtl.Seconds())),
	}

	if config.DNSSECPrivateKeyFile != "" {
		fh, err := os.Open(config.DNSSECPublicKeyFile)
		if err != nil {
			panic(err)
		}
		pubkey, err := dns.ReadRR(fh, config.DNSSECPublicKeyFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}

		hdl.dnssecDNSKEY = pubkey.(*dns.DNSKEY)

		fh, err = os.Open(config.DNSSECPrivateKeyFile)
		if err != nil {
			panic(err)
		}
		hdl.dnssecPrivateKey, err = hdl.dnssecDNSKEY.ReadPrivateKey(fh, config.DNSSECPrivateKeyFile)
		_ = fh.Close()
		if err != nil {
			panic(err)
		}
	}

	nsTtl := uint32(config.NSTtl.Seconds())
	for _, ns := range config.Nameservers {
		hdl.ns = append(hdl.ns, FillAuthHeader(&dns.NS{
			Ns: dns.CanonicalName(ns),
		}, dns.TypeNS, zone, nsTtl))
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
			if r.dnssecDNSKEY != nil {
				reply.Answer = []dns.RR{r.dnssecDNSKEY}
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

	if r.dnssecDNSKEY != nil && len(reply.Answer) > 0 {
		queryEDNS0 := msg.IsEdns0()
		dnssecOK := false
		if queryEDNS0 != nil {
			dnssecOK = queryEDNS0.Do()
		}
		if dnssecOK {
			signer := &dns.RRSIG{}
			ttl := reply.Answer[0].Header().Ttl
			util.FillHeader(signer, r.zone, dns.TypeRRSIG, ttl)
			signer.TypeCovered = reply.Answer[0].Header().Rrtype
			signer.Labels = uint8(dns.CountLabel(reply.Answer[0].Header().Name))
			signer.OrigTtl = ttl
			signer.Expiration = uint32(time.Now().Add(86400 * time.Second).Unix())
			signer.Inception = uint32(time.Now().Unix())
			signer.KeyTag = r.dnssecDNSKEY.KeyTag()
			signer.SignerName = r.zone
			signer.Algorithm = r.dnssecDNSKEY.Algorithm
			err := signer.Sign(r.dnssecPrivateKey.(*ecdsa.PrivateKey), reply.Answer)
			if err != nil {
				log.Printf("Error signing record for %s: %v", reply.Answer[0].Header().Name, err)
			} else {
				reply.Answer = append(reply.Answer, signer)
			}
		}
	}
}

func (r *AuthorityHandler) Register(mux *dns.ServeMux) {
	mux.Handle(r.zone, r)
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
