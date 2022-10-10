package rdns

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type RDNSv4Generator struct {
	PTRSuffix string
}

func (r *RDNSv4Generator) servePTR(name string) dns.RR {
	nameSplit := strings.Split(name, ".")

	if len(nameSplit) != 7 {
		return nil
	}

	ipv4 := net.IP(make([]byte, net.IPv4len))
	for i := 0; i < 4; i++ {
		r, err := strconv.Atoi(nameSplit[3-i])
		if err != nil || r < 0 || r > 0xFF {
			return nil
		}
		ipv4[i] = byte(r)
	}

	return &dns.PTR{
		Ptr: fmt.Sprintf("%s.%s.", strings.ReplaceAll(ipv4.String(), ".", "-"), r.PTRSuffix),
	}
}

func (r *RDNSv4Generator) serveA(name string) dns.RR {
	nameSplit := strings.Split(name, ".")
	if len(nameSplit) < 2 {
		return nil
	}

	rdnsV4 := strings.ReplaceAll(nameSplit[0], "-", ".")
	ipv4 := net.ParseIP(rdnsV4)
	if ipv4 == nil {
		return nil
	}

	return &dns.A{
		A: ipv4,
	}
}

func (r *RDNSv4Generator) HandleQuestion(q dns.Question) []dns.RR {
	var resp dns.RR

	switch q.Qtype {
	case dns.TypePTR:
		resp = r.servePTR(q.Name)
	case dns.TypeA:
		resp = r.serveA(q.Name)
	}

	if resp == nil {
		return []dns.RR{}
	}

	util.FillHeader(resp, q.Name, q.Qtype, 3600)

	return []dns.RR{resp}
}
