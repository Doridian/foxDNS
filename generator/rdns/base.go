package rdns

import (
	"fmt"
	"net"
	"strings"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type Generator struct {
	PTRSuffix string

	recordType  uint16
	ipSegments  int
	ipSeparator string

	decodeIpSegments func(nameSplit []string) net.IP
	makeRec          func(net.IP) dns.RR
}

func (r *Generator) servePTR(name string) dns.RR {
	nameSplit := strings.Split(name, ".")

	if len(nameSplit) != r.ipSegments+3 {
		return nil
	}

	ip := r.decodeIpSegments(nameSplit[:r.ipSegments])

	return &dns.PTR{
		Ptr: fmt.Sprintf("%s.%s.", strings.ReplaceAll(ip.String(), r.ipSeparator, "-"), r.PTRSuffix),
	}
}

func (r *Generator) serveRec(name string) dns.RR {
	nameSplit := strings.Split(name, ".")
	if len(nameSplit) < 2 {
		return nil
	}

	rdnsStr := strings.ReplaceAll(nameSplit[0], "-", r.ipSeparator)
	rdnsIp := net.ParseIP(rdnsStr)
	if rdnsIp == nil {
		return nil
	}

	return r.makeRec(rdnsIp)
}

func (r *Generator) HandleQuestion(q dns.Question, _ dns.ResponseWriter) ([]dns.RR, bool) {
	var resp dns.RR

	switch q.Qtype {
	case dns.TypePTR:
		resp = r.servePTR(q.Name)
	case r.recordType:
		resp = r.serveRec(q.Name)
	}

	if resp == nil {
		return []dns.RR{}, false
	}

	util.FillHeader(resp, q.Name, q.Qtype, 3600)

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
