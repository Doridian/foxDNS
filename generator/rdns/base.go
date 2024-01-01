package rdns

import (
	"fmt"
	"net"
	"strings"

	"github.com/Doridian/foxDNS/generator/simple"
	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type Generator struct {
	ptrSuffix  string
	AddressTtl uint32
	PtrTtl     uint32

	recordType  uint16
	ipSegments  int
	ipSeparator string
	arpaSuffix  string

	AllowedSubnets []*net.IPNet

	decodeIpSegments func(nameSplit []string) net.IP
	encodeIp         func(ip net.IP) string
	makeRec          func(net.IP) dns.RR

	addPTRZones func(r *Generator, zones []string) []string
}

func (r *Generator) SetPTRSuffix(ptrSuffix string) {
	if !strings.HasSuffix(ptrSuffix, ".") {
		ptrSuffix += "."
	}
	r.ptrSuffix = ptrSuffix
}

func (r *Generator) servePTR(name string) dns.RR {
	nameSplit := strings.SplitN(name, ".", r.ipSegments+1)
	if len(nameSplit) != r.ipSegments+1 {
		return nil
	}

	if nameSplit[r.ipSegments] != r.arpaSuffix {
		return nil
	}

	ip := r.decodeIpSegments(nameSplit[:r.ipSegments])
	if ip == nil {
		return nil
	}

	if !r.isAllowed(ip) {
		return nil
	}

	return &dns.PTR{
		Ptr: fmt.Sprintf("%s.%s", r.encodeIp(ip), r.ptrSuffix),
	}
}

func (r *Generator) serveRec(name string) dns.RR {
	nameSplit := strings.SplitN(name, ".", 2)
	if len(nameSplit) != 2 {
		return nil
	}

	if nameSplit[1] != r.ptrSuffix {
		return nil
	}

	rdnsStr := strings.ReplaceAll(nameSplit[0], "-", r.ipSeparator)
	rdnsIp := net.ParseIP(rdnsStr)
	if rdnsIp == nil {
		return nil
	}

	if !r.isAllowed(rdnsIp) {
		return nil
	}

	return r.makeRec(rdnsIp)
}

func (r *Generator) isAllowed(ip net.IP) bool {
	for _, subnet := range r.AllowedSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *Generator) HandleQuestion(q *dns.Question, _ simple.DNSResponseWriter) ([]dns.RR, bool) {
	var resp dns.RR
	var ttl uint32

	switch q.Qtype {
	case dns.TypePTR:
		resp = r.servePTR(q.Name)
		ttl = r.PtrTtl
	case r.recordType:
		resp = r.serveRec(q.Name)
		ttl = r.AddressTtl
	}

	if resp == nil {
		return []dns.RR{}, false
	}

	util.FillHeader(resp, q.Name, q.Qtype, ttl)

	return []dns.RR{resp}, false
}

func (r *Generator) Refresh() error {
	return nil
}

func (r *Generator) Start() error {
	return nil
}

func (r *Generator) Stop() error {
	return nil
}

func (r *Generator) GetName() string {
	return "rdns"
}

func (r *Generator) GetZones() []string {
	res := []string{r.ptrSuffix}
	res = r.addPTRZones(r, res)
	return res
}
