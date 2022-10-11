package localizer

import (
	"net"

	"github.com/FoxDenHome/foxdns/util"
	"github.com/miekg/dns"
)

type LocalizerRecordMap = map[string][]*LocalizerRecord

type LocalizerRecord struct {
	Subnet *net.IPNet
	IP     net.IP
}

type LocalizedRecordGenerator struct {
	ARecords    LocalizerRecordMap
	AAAARecords LocalizerRecordMap
}

func NewLocalizer() *LocalizedRecordGenerator {
	return &LocalizedRecordGenerator{
		ARecords:    make(LocalizerRecordMap),
		AAAARecords: make(LocalizerRecordMap),
	}
}

func (r *LocalizedRecordGenerator) AddRecord(hostStr string, subnetStr string) error {
	hostStr = dns.CanonicalName(hostStr)

	ip, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return err
	}

	ipv4 := ip.To4()
	if ipv4 != nil {
		ip = ipv4
	}

	rec := &LocalizerRecord{
		Subnet: subnet,
		IP:     ip,
	}

	var recMap LocalizerRecordMap
	switch len(ip) {
	case net.IPv4len:
		recMap = r.ARecords
	case net.IPv6len:
		recMap = r.AAAARecords
	}

	recArr := recMap[hostStr]
	if recArr == nil {
		recArr = make([]*LocalizerRecord, 0)
	}
	recArr = append(recArr, rec)
	recMap[hostStr] = recArr

	return nil
}

func makeRecV4(ip net.IP) dns.RR {
	return &dns.A{
		A: ip,
	}
}

func makeRecV6(ip net.IP) dns.RR {
	return &dns.AAAA{
		AAAA: ip,
	}
}

func (r *LocalizedRecordGenerator) HandleQuestion(q dns.Question, wr dns.ResponseWriter) []dns.RR {
	var makeRecFunc func(net.IP) dns.RR
	var recsMap LocalizerRecordMap

	switch q.Qtype {
	case dns.TypeA:
		recsMap = r.ARecords
		makeRecFunc = makeRecV4
	case dns.TypeAAAA:
		recsMap = r.AAAARecords
		makeRecFunc = makeRecV6
	}

	if recsMap == nil {
		return []dns.RR{}
	}

	recs := recsMap[q.Name]
	if recs == nil {
		return []dns.RR{}
	}

	remoteIP := util.ExtractIP(wr.RemoteAddr())

	if remoteIP == nil {
		return []dns.RR{}
	}

	remoteIPv4 := remoteIP.To4()
	if remoteIPv4 != nil {
		remoteIP = remoteIPv4
	}

	resp := make([]dns.RR, 0, len(recs))
	for _, rec := range recs {
		ipRec := IPNetAdd(rec.Subnet, rec.IP, remoteIP)
		ipResRec := makeRecFunc(ipRec)
		util.FillHeader(ipResRec, q.Name, q.Qtype, 60)
		resp = append(resp, ipResRec)
	}
	return resp
}
