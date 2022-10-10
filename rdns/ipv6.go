package rdns

import (
	"net"

	"github.com/miekg/dns"
)

func ipv6Decode(nameSplit []string) net.IP {
	ip := net.IP(make([]byte, net.IPv6len))
	for i := 0; i < 16; i++ {
		j := 30 - (i * 2)
		ip[i] = twoStringByteToByte(nameSplit[j], nameSplit[j+1])
	}
	return ip
}

func ipv6MakeRec(ip net.IP) dns.RR {
	ip = ip.To16()
	if ip == nil {
		return nil
	}

	return &dns.AAAA{
		AAAA: ip,
	}
}

func NewRDNSv6Generator() *RDNSGenerator {
	return &RDNSGenerator{
		recordType:  dns.TypeAAAA,
		ipSegments:  32,
		ipSeparator: ":",

		decodeIpSegments: ipv6Decode,
		makeRec:          ipv6MakeRec,
	}
}
