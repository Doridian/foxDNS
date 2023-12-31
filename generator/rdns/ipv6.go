package rdns

import (
	"fmt"
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

func ipv6Encode(ip net.IP) string {
	return fmt.Sprintf("%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}

func ipv6AddPTRZones(zones []string) []string {
	return zones
}

func NewIPv6() *Generator {
	return &Generator{
		AddressTtl: 3600,
		PtrTtl:     3600,

		recordType:  dns.TypeAAAA,
		ipSegments:  32,
		ipSeparator: ":",

		decodeIpSegments: ipv6Decode,
		encodeIp:         ipv6Encode,
		makeRec:          ipv6MakeRec,
		addPTRZones:      ipv6AddPTRZones,
	}
}
