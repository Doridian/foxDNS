package rdns

import (
	"fmt"
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

func ipv4Encode(ip net.IP) string {
	return fmt.Sprintf("%d-%d-%d-%d", ip[0], ip[1], ip[2], ip[3])
}

func NewIPv4() *Generator {
	return &Generator{
		AddressTtl: 3600,
		PtrTtl:     3600,

		recordType:  dns.TypeA,
		ipSegments:  4,
		ipSeparator: ".",

		decodeIpSegments: ipv4Decode,
		encodeIp:         ipv4Encode,
		makeRec:          ipv4MakeRec,
	}
}
