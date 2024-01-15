package localizer

import (
	"fmt"
	"net"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type LocalizerRecordMap = map[string][]*LocalizerRecord
type LocalizerRewrite struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

type localizerRewriteParsed struct {
	FromSubnet *net.IPNet
	FromIP     net.IP
	To         net.IP
}

type LocalizerRecord struct {
	Subnet   *net.IPNet
	IP       net.IP
	Rewrites []localizerRewriteParsed
}

type LocalizedRecordGenerator struct {
	aRecords    LocalizerRecordMap
	aaaaRecords LocalizerRecordMap
	knownHosts  map[string]bool
	Ttl         uint32
}

func New() *LocalizedRecordGenerator {
	return &LocalizedRecordGenerator{
		aRecords:    make(LocalizerRecordMap),
		aaaaRecords: make(LocalizerRecordMap),
		knownHosts:  make(map[string]bool),
		Ttl:         60,
	}
}

func (r *LocalizedRecordGenerator) AddRecord(hostStr string, subnetStr string, rewrites []LocalizerRewrite) error {
	if rewrites == nil {
		rewrites = make([]LocalizerRewrite, 0)
	}

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
		Subnet:   subnet,
		IP:       ip,
		Rewrites: make([]localizerRewriteParsed, 0, len(rewrites)),
	}

	for _, rewrite := range rewrites {
		fromIP, fromSubnet, err := net.ParseCIDR(rewrite.From)
		if err != nil {
			return err
		}
		toIP := net.ParseIP(rewrite.To)
		if toIP == nil {
			return fmt.Errorf("invalid to IP: %s", rewrite.To)
		}
		toIPv4 := toIP.To4()
		if toIPv4 != nil {
			toIP = toIPv4
		}
		rec.Rewrites = append(rec.Rewrites, localizerRewriteParsed{
			FromIP:     fromIP,
			FromSubnet: fromSubnet,
			To:         toIP,
		})
	}

	var recMap LocalizerRecordMap
	switch len(ip) {
	case net.IPv4len:
		recMap = r.aRecords
	case net.IPv6len:
		recMap = r.aaaaRecords
	}

	recArr := recMap[hostStr]
	if recArr == nil {
		recArr = make([]*LocalizerRecord, 0)
	}
	recArr = append(recArr, rec)
	recMap[hostStr] = recArr

	r.knownHosts[hostStr] = true

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

func (r *LocalizedRecordGenerator) HandleQuestion(q *dns.Question, wr util.SimpleDNSResponseWriter) ([]dns.RR, bool) {
	if !r.knownHosts[q.Name] {
		return []dns.RR{}, true
	}

	var makeRecFunc func(net.IP) dns.RR
	var recsMap LocalizerRecordMap

	switch q.Qtype {
	case dns.TypeA:
		recsMap = r.aRecords
		makeRecFunc = makeRecV4
	case dns.TypeAAAA:
		recsMap = r.aaaaRecords
		makeRecFunc = makeRecV6
	}

	if recsMap == nil {
		return []dns.RR{}, false
	}

	recs := recsMap[q.Name]
	if recs == nil {
		return []dns.RR{}, false
	}

	remoteIP := util.ExtractIP(wr.RemoteAddr())

	if remoteIP == nil {
		return []dns.RR{}, false
	}

	remoteIPv4 := remoteIP.To4()
	if remoteIPv4 != nil {
		remoteIP = remoteIPv4
	}

	resp := make([]dns.RR, 0, len(recs))
	for _, rec := range recs {
		ipRec := IPNetAdd(rec.Subnet, rec.IP, remoteIP)
		if ipRec == nil {
			continue
		}

		for _, rewrite := range rec.Rewrites {
			if rewrite.FromSubnet.Contains(ipRec) {
				ipRec = IPNetAdd(rewrite.FromSubnet, ipRec, rewrite.To)
				break
			}
		}

		ipResRec := makeRecFunc(ipRec)
		util.FillHeader(ipResRec, q.Name, q.Qtype, r.Ttl)
		resp = append(resp, ipResRec)
	}
	return resp, false
}

func (r *LocalizedRecordGenerator) Refresh() error {
	return nil
}

func (r *LocalizedRecordGenerator) Start() error {
	return nil
}

func (r *LocalizedRecordGenerator) Stop() error {
	return nil
}

func (r *LocalizedRecordGenerator) GetName() string {
	return "localizer"
}
