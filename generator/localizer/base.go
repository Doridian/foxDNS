package localizer

import (
	"fmt"
	"net"

	"github.com/Doridian/foxDNS/util"
	"github.com/miekg/dns"
)

type localizerRecordMap = map[string][]*localizerRecord

type LocalizerRewrite struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

type V4V6Rewrite struct {
	V4 string `yaml:"v4"`
	V6 string `yaml:"v6"`
}

type v4v6RewriteParsed struct {
	v4 *net.IPNet
	v6 *net.IPNet
}

type localizerRewriteParsed struct {
	fromSubnet *net.IPNet
	fromIP     net.IP
	toSubnet   *net.IPNet
	toIP       net.IP
}

type localizerRecord struct {
	subnet *net.IPNet
	ip     net.IP
}

type LocalizedRecordGenerator struct {
	aRecords   localizerRecordMap
	v4rewrites []localizerRewriteParsed

	aaaaRecords localizerRecordMap
	v6rewrites  []localizerRewriteParsed

	v4V6s []v4v6RewriteParsed

	knownHosts map[string]bool
	Ttl        uint32
}

func New() *LocalizedRecordGenerator {
	return &LocalizedRecordGenerator{
		aRecords:   make(localizerRecordMap),
		v4rewrites: make([]localizerRewriteParsed, 0),

		aaaaRecords: make(localizerRecordMap),
		v6rewrites:  make([]localizerRewriteParsed, 0),

		v4V6s: make([]v4v6RewriteParsed, 0),

		knownHosts: make(map[string]bool),
		Ttl:        60,
	}
}

func (r *LocalizedRecordGenerator) AddV4V6s(v4v6s []V4V6Rewrite) error {
	for _, v4v6 := range v4v6s {
		_, v4, err := net.ParseCIDR(v4v6.V4)
		if err != nil || v4.IP.To4() == nil {
			return fmt.Errorf("invalid v4 CIDR: %s (%v)", v4v6.V4, err)
		}
		_, v6, err := net.ParseCIDR(v4v6.V6)
		if v6 == nil || v6.IP.To4() != nil {
			return fmt.Errorf("invalid v6 CIDR: %s (%v)", v4v6.V4, err)
		}
		r.v4V6s = append(r.v4V6s, v4v6RewriteParsed{
			v4: v4,
			v6: v6,
		})
	}
	return nil
}

func (r *LocalizedRecordGenerator) AddRewrites(rewrites []LocalizerRewrite) error {
	for _, rewrite := range rewrites {
		fromIP, fromSubnet, err := net.ParseCIDR(rewrite.From)
		if err != nil {
			return err
		}
		fromIPv4 := fromIP.To4()
		fromIsIPv4 := fromIPv4 != nil
		if fromIsIPv4 {
			fromIP = fromIPv4
		}
		toIP, toSubnet, err := net.ParseCIDR(rewrite.To)
		if err != nil {
			return err
		}
		toIPv4 := toIP.To4()
		toIsIPv4 := toIPv4 != nil
		if toIsIPv4 {
			toIP = toIPv4
		}

		if toIsIPv4 != fromIsIPv4 {
			return fmt.Errorf("rewrite from %s to %s has mismatched IP versions", rewrite.From, rewrite.To)
		}

		parsed := localizerRewriteParsed{
			fromSubnet: fromSubnet,
			fromIP:     fromIP,
			toSubnet:   toSubnet,
			toIP:       toIP,
		}

		if fromIsIPv4 {
			r.v4rewrites = append(r.v4rewrites, parsed)
		} else {
			r.v6rewrites = append(r.v6rewrites, parsed)
		}
	}

	return nil
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

	rec := &localizerRecord{
		subnet: subnet,
		ip:     ip,
	}

	var recMap localizerRecordMap
	switch len(ip) {
	case net.IPv4len:
		recMap = r.aRecords
	case net.IPv6len:
		recMap = r.aaaaRecords
	}

	recArr := recMap[hostStr]
	if recArr == nil {
		recArr = make([]*localizerRecord, 0)
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
	var recsMap localizerRecordMap
	var recordIsV4 bool

	switch q.Qtype {
	case dns.TypeA:
		recordIsV4 = true
		recsMap = r.aRecords
		makeRecFunc = makeRecV4
	case dns.TypeAAAA:
		recordIsV4 = false
		recsMap = r.aaaaRecords
		makeRecFunc = makeRecV6
	}

	if recsMap == nil {
		return []dns.RR{}, false
	}

	recs := recsMap[q.Name]
	if len(recs) < 1 {
		return []dns.RR{}, false
	}

	remoteIP := util.ExtractIP(wr.RemoteAddr())

	if remoteIP == nil {
		return []dns.RR{}, false
	}

	remoteIPv4 := remoteIP.To4()
	rewrites := r.v6rewrites
	remoteIPIsV4 := remoteIPv4 != nil
	if remoteIPIsV4 {
		remoteIP = remoteIPv4
		rewrites = r.v4rewrites
	}

	for _, rewrite := range rewrites {
		if rewrite.fromSubnet.Contains(remoteIP) {
			remoteIP = IPNetAdd(rewrite.toSubnet, remoteIP, rewrite.toIP)
			break
		}
	}

	foundLocalIP := remoteIPIsV4 == recordIsV4
	if !foundLocalIP {
		remoteIPBase := remoteIP.To16()
		if recordIsV4 {
			remoteIPBase = remoteIP[len(remoteIP)-net.IPv4len:]
		}

		for _, v4v6Rewrite := range r.v4V6s {
			remoteBase := v4v6Rewrite.v6
			recordBase := v4v6Rewrite.v6
			if recordIsV4 {
				recordBase = v4v6Rewrite.v4
			}
			if remoteIPIsV4 {
				remoteBase = v4v6Rewrite.v4
			}

			if remoteBase.Contains(remoteIP) {
				remoteIP = IPNetAdd(recordBase, remoteIPBase, recordBase.IP)
				foundLocalIP = true
				break
			}
		}

		if !foundLocalIP {
			return []dns.RR{}, false
		}
	}

	resp := make([]dns.RR, 0, len(recs))
	for _, rec := range recs {
		ipRec := IPNetAdd(rec.subnet, rec.ip, remoteIP)
		if ipRec == nil {
			continue
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
