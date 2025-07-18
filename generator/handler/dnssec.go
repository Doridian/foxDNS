package handler

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (h *Handler) signResponse(q *dns.Question, answer []dns.RR) (dns.RR, error) {
	dnskey := h.zskDNSKEY
	privkey := h.zskPrivateKey
	if q.Qtype == dns.TypeDNSKEY {
		dnskey = h.kskDNSKEY
		privkey = h.kskPrivateKey
	}

	if dnskey == nil || privkey == nil {
		return nil, nil
	}

	if len(answer) == 0 {
		// TODO: NSEC3, maybe, probably not
		return nil, nil
	}

	cacheKey := fmt.Sprintf("%s:%d:%d", q.Name, q.Qclass, q.Qtype)

	if h.enableSignatureCache {
		h.signatureLock.Lock()
		defer h.signatureLock.Unlock()
		oldSigner := h.signatures[cacheKey]
		if oldSigner != nil && oldSigner.Expiration > uint32(time.Now().Add(time.Second*60).Unix()) {
			return oldSigner, nil
		}
		delete(h.signatures, cacheKey)
	}

	signer := &dns.RRSIG{}
	ttl := answer[0].Header().Ttl
	util.FillHeader(signer, h.zone, dns.TypeRRSIG, ttl)
	signer.TypeCovered = answer[0].Header().Rrtype
	signer.Labels = uint8(dns.CountLabel(answer[0].Header().Name))
	signer.OrigTtl = ttl
	signer.Expiration = uint32(time.Now().Add(3600 * time.Second).Unix())
	signer.Inception = uint32(time.Now().Unix())
	signer.SignerName = h.signerName

	signer.KeyTag = dnskey.KeyTag()
	signer.Algorithm = dnskey.Algorithm
	err := signer.Sign(privkey.(*ecdsa.PrivateKey), answer)
	if err == nil && h.enableSignatureCache {
		h.signatures[cacheKey] = signer
	}
	return signer, err
}
