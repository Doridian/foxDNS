package rdns

import (
	"net"

	"github.com/miekg/dns"
)

func ipv6Decode(nameSplit []string) net.IP {
	var ok bool
	ip := net.IP(make([]byte, net.IPv6len))
	for i := 0; i < 16; i++ {
		j := 30 - (i * 2)
		ip[i], ok = twoStringByteToByte(nameSplit[j], nameSplit[j+1])
		if !ok {
			return nil
		}
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

func NewIPv6() *Generator {
	return &Generator{
		recordType:  dns.TypeAAAA,
		ipSegments:  32,
		ipSeparator: ":",

		decodeIpSegments: ipv6Decode,
		makeRec:          ipv6MakeRec,
	}
}
