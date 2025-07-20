package generator

import (
	"crypto"
	"sync"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type Handler struct {
	child Generator
	mux   *dns.ServeMux

	RequireCookie bool
	soa           []dns.RR
	ns            []dns.RR

	zone          string
	authoritative bool

	enableSignatureCache bool
	signatureLock        sync.Mutex
	signatures           map[string]*dns.RRSIG
	zskDNSKEY            *dns.DNSKEY
	zskPrivateKey        crypto.PrivateKey
	kskDNSKEY            *dns.DNSKEY
	kskPrivateKey        crypto.PrivateKey

	recursionAvailable bool
}

func New(mux *dns.ServeMux, child Generator, zone string, config Config) *Handler {
	hdl := &Handler{
		child: child,
		mux:   mux,
	}
	hdl.loadConfig(config, dns.CanonicalName(zone))
	return hdl
}

func (h *Handler) clearCache() {
	h.signatureLock.Lock()
	h.signatures = make(map[string]*dns.RRSIG)
	h.signatureLock.Unlock()
}

func (h *Handler) Refresh() error {
	h.clearCache()
	return nil
}

func (h *Handler) Start() error {
	h.clearCache()
	return nil
}

func (h *Handler) Stop() error {
	h.clearCache()
	return nil
}

func FillAuthHeader(rr dns.RR, rtype uint16, zone string, ttl uint32) dns.RR {
	return util.FillHeader(rr, zone, rtype, ttl)
}
