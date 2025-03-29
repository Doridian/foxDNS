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

type V4V6Rewrite struct {
	V4 string `yaml:"v4"`
	V6 string `yaml:"v6"`
}

type v4v6RewriteParsed struct {
	V4 *net.IPNet
	V6 *net.IPNet
}

type localizerRewriteParsed struct {
	FromSubnet *net.IPNet
	FromIP     net.IP
	ToSubnet   *net.IPNet
	ToIP       net.IP
}

type LocalizerRecord struct {
	Subnet   *net.IPNet
	IP       net.IP
	Rewrites []localizerRewriteParsed
	V4V6s    []v4v6RewriteParsed
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

func (r *LocalizedRecordGenerator) AddRecord(hostStr string, subnetStr string, rewrites []LocalizerRewrite, v4v6s []V4V6Rewrite) error {
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
		V4V6s:    make([]v4v6RewriteParsed, 0, len(v4v6s)),
	}

	for _, rewrite := range rewrites {
		fromIP, fromSubnet, err := net.ParseCIDR(rewrite.From)
		if err != nil {
			return err
		}
		toIP, toSubnet, err := net.ParseCIDR(rewrite.To)
		if err != nil {
			return err
		}
		toIPv4 := toIP.To4()
		if toIPv4 != nil {
			toIP = toIPv4
		}
		rec.Rewrites = append(rec.Rewrites, localizerRewriteParsed{
			FromSubnet: fromSubnet,
			FromIP:     fromIP,
			ToSubnet:   toSubnet,
			ToIP:       toIP,
		})
	}

	for _, v4v6 := range v4v6s {
		_, v4, err := net.ParseCIDR(v4v6.V4)
		if err != nil || v4.IP.To4() == nil {
			return fmt.Errorf("invalid v4 CIDR: %s (%v)", v4v6.V4, err)
		}
		_, v6, err := net.ParseCIDR(v4v6.V6)
		if v6 == nil || v6.IP.To4() != nil {
			return fmt.Errorf("invalid v6 CIDR: %s (%v)", v4v6.V4, err)
		}
		rec.V4V6s = append(rec.V4V6s, v4v6RewriteParsed{
			V4: v4,
			V6: v6,
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
	ipIsV4 := remoteIPv4 != nil
	if ipIsV4 {
		remoteIP = remoteIPv4
	}

	resp := make([]dns.RR, 0, len(recs))
	for _, rec := range recs {
		foundLocalIP := false
		if ipIsV4 && q.Qtype == dns.TypeAAAA {
			for _, v4v6Rewrite := range rec.V4V6s {
				if v4v6Rewrite.V4.Contains(remoteIP) {
					remoteIP = IPNetAdd(v4v6Rewrite.V6, remoteIP.To16(), v4v6Rewrite.V6.IP)
					foundLocalIP = true
					break
				}
			}
		} else if !ipIsV4 && q.Qtype == dns.TypeA {
			for _, v4v6Rewrite := range rec.V4V6s {
				if v4v6Rewrite.V6.Contains(remoteIP) {
					remoteIP = IPNetAdd(v4v6Rewrite.V4, remoteIP[len(remoteIP)-net.IPv4len:], v4v6Rewrite.V4.IP)
					foundLocalIP = true
					break
				}
			}
		} else {
			foundLocalIP = true
		}

		if !foundLocalIP {
			continue
		}

		ipRec := IPNetAdd(rec.Subnet, rec.IP, remoteIP)
		if ipRec == nil {
			continue
		}

		for _, rewrite := range rec.Rewrites {
			if rewrite.FromSubnet.Contains(ipRec) {
				ipRec = IPNetAdd(rewrite.ToSubnet, ipRec, rewrite.ToIP)
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
