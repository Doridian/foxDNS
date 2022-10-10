package rdns

import (
	"fmt"
	"net"
	"strings"

	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type RDNSv6Generator struct {
	PTRSuffix string
}

func (r *RDNSv6Generator) servePTR(name string) dns.RR {
	nameSplit := strings.Split(name, ".")
	if len(nameSplit) != 35 {
		return nil
	}

	ipv6 := net.IP(make([]byte, net.IPv6len))
	for i := 0; i < 16; i++ {
		j := 30 - (i * 2)
		ipv6[i] = twoStringByteToByte(nameSplit[j], nameSplit[j+1])
	}

	return &dns.PTR{
		Ptr: fmt.Sprintf("%s.%s.", strings.ReplaceAll(ipv6.String(), ":", "-"), r.PTRSuffix),
	}
}

func (r *RDNSv6Generator) serveAAAA(name string) dns.RR {
	nameSplit := strings.Split(name, ".")
	if len(nameSplit) < 2 {
		return nil
	}

	rdnsV6 := strings.ReplaceAll(nameSplit[0], "-", ":")
	ipv6 := net.ParseIP(rdnsV6)
	if ipv6 == nil {
		return nil
	}
	ipv6 = ipv6.To16()
	if ipv6 == nil {
		return nil
	}

	return &dns.AAAA{
		AAAA: ipv6,
	}
}

func (r *RDNSv6Generator) HandleQuestion(q dns.Question) []dns.RR {
	var resp dns.RR

	switch q.Qtype {
	case dns.TypePTR:
		resp = r.servePTR(q.Name)
	case dns.TypeAAAA:
		resp = r.serveAAAA(q.Name)
	}

	if resp == nil {
		return []dns.RR{}
	}

	util.FillHeader(resp, q.Name, q.Qtype, 3600)

	return []dns.RR{resp}
}
