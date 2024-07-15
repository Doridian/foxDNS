package authority

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

func (r *AuthorityHandler) signResponse(q *dns.Question, msg *dns.Msg, answer []dns.RR) (dns.RR, error) {
	queryEDNS0 := msg.IsEdns0()
	if queryEDNS0 == nil || !queryEDNS0.Do() {
		return nil, nil
	}

	if len(answer) == 0 {
		// TODO: NSEC3, maybe, probably not
		return nil, nil
	}

	cacheKey := fmt.Sprintf("%s:%d:%d", q.Name, q.Qclass, q.Qtype)

	if r.enableSignatureCache {
		r.signatureLock.Lock()
		defer r.signatureLock.Unlock()
		oldSigner := r.signatures[cacheKey]
		if oldSigner != nil && oldSigner.Expiration > uint32(time.Now().Add(time.Second*60).Unix()) {
			return oldSigner, nil
		}
		delete(r.signatures, cacheKey)
	}

	signer := &dns.RRSIG{}
	ttl := answer[0].Header().Ttl
	util.FillHeader(signer, r.zone, dns.TypeRRSIG, ttl)
	signer.TypeCovered = answer[0].Header().Rrtype
	signer.Labels = uint8(dns.CountLabel(answer[0].Header().Name))
	signer.OrigTtl = ttl
	signer.Expiration = uint32(time.Now().Add(3600 * time.Second).Unix())
	signer.Inception = uint32(time.Now().Unix())
	signer.SignerName = r.signerName

	dnskey := r.zskDNSKEY
	privkey := r.zskPrivateKey
	if q.Qtype == dns.TypeDNSKEY {
		dnskey = r.kskDNSKEY
		privkey = r.kskPrivateKey
	}

	signer.KeyTag = dnskey.KeyTag()
	signer.Algorithm = dnskey.Algorithm
	err := signer.Sign(privkey.(*ecdsa.PrivateKey), answer)
	if err == nil && r.enableSignatureCache {
		r.signatures[cacheKey] = signer
	}
	return signer, err
}
