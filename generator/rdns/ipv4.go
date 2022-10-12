package rdns

import (
	"net"
	"strconv"

	"github.com/miekg/dns"
)

func ipv4Decode(nameSplit []string) net.IP {
	ip := net.IP(make([]byte, net.IPv4len))
	for i := 0; i < 4; i++ {
		r, err := strconv.Atoi(nameSplit[3-i])
		if err != nil || r < 0 || r > 0xFF {
			return nil
		}
		ip[i] = byte(r)
	}
	return ip
}

func ipv4MakeRec(ip net.IP) dns.RR {
	ip = ip.To4()
	if ip == nil {
		return nil
	}

	return &dns.A{
		A: ip,
	}
}

func NewIPv4() *Generator {
	return &Generator{
		recordType:  dns.TypeA,
		ipSegments:  4,
		ipSeparator: ".",

		decodeIpSegments: ipv4Decode,
		makeRec:          ipv4MakeRec,
	}
}
