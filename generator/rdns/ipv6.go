package rdns

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

const ipv6ArpaSuffix = "ip6.arpa."

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

func ipv6AddPTRZones(r *Generator, zones []string) []string {
	for _, subnet := range r.AllowedSubnets {
		subnetIP := subnet.IP.To16()
		ones, _ := subnet.Mask.Size()
		if ones == 0 {
			log.Panicf("invalid subnet %v", subnet)
		}

		fullPieces := ones / 8
		leftoverBits := ones % 8

		zoneRecordPieces := make([]string, 0, net.IPv6len+1)
		for i := fullPieces - 1; i >= 0; i-- {
			zoneRecordPieces = append(zoneRecordPieces, fmt.Sprintf("%x.%x", subnetIP[i]&0xF, subnetIP[i]>>4))
		}
		zoneRecordPieces = append(zoneRecordPieces, ipv6ArpaSuffix)

		fullZoneName := strings.Join(zoneRecordPieces, ".")
		if leftoverBits == 0 {
			zones = append(zones, fullZoneName)
			continue
		}

		if leftoverBits >= 4 {
			fullZoneName = fmt.Sprintf("%x.%s", subnetIP[fullPieces]>>4, fullZoneName)
			leftoverBits -= 4
			if leftoverBits == 0 {
				zones = append(zones, fullZoneName)
				continue
			}
		}

		for i := 0; i < 1<<(4-leftoverBits); i++ {
			zones = append(zones, fmt.Sprintf("%x.%s", i+int(subnetIP[fullPieces]&0xF), fullZoneName))
		}
	}
	return zones
}

func NewIPv6() *Generator {
	return &Generator{
		AddressTtl: 3600,
		PtrTtl:     3600,

		recordType:  dns.TypeAAAA,
		ipSegments:  32,
		ipSeparator: ":",
		arpaSuffix:  ipv6ArpaSuffix,

		decodeIpSegments: ipv6Decode,
		encodeIp:         ipv6Encode,
		makeRec:          ipv6MakeRec,
		addPTRZones:      ipv6AddPTRZones,
	}
}
