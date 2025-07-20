package rdns

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

const ipv4ArpaSuffix = "in-addr.arpa."

func ipv4Decode(nameSplit []string) net.IP {
	ip := net.IP(make([]byte, net.IPv4len))
	for i := 0; i < 4; i++ {
		r, err := strconv.Atoi(nameSplit[3-i])
		if err != nil || r < 0 || r > 255 {
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

func ipv4AddPTRZones(r *Generator) []string {
	zones := make([]string, 0, len(r.AllowedSubnets))

	for _, subnet := range r.AllowedSubnets {
		subnetIP := subnet.IP.To4()
		ones, _ := subnet.Mask.Size()
		if ones == 0 {
			log.Panicf("invalid subnet %v", subnet)
		}

		leftoverBits := ones % 8
		fullPieces := ones / 8

		zoneRecordPieces := make([]string, 0, net.IPv4len+1)
		for i := fullPieces - 1; i >= 0; i-- {
			zoneRecordPieces = append(zoneRecordPieces, fmt.Sprintf("%d", subnetIP[i]))
		}
		zoneRecordPieces = append(zoneRecordPieces, ipv4ArpaSuffix)

		fullZoneName := strings.Join(zoneRecordPieces, ".")

		// We stopped right at a octet boundary, so we can just add the full zone
		if leftoverBits == 0 {
			zones = append(zones, fullZoneName)
			continue
		}

		// We need to add the possibilities for the non-fully-fixed octets
		for i := 0; i < 1<<(8-leftoverBits); i++ {
			zones = append(zones, fmt.Sprintf("%d.%s", i+int(subnetIP[fullPieces]), fullZoneName))
		}
	}

	return zones
}

func NewIPv4() *Generator {
	return &Generator{
		AddressTtl: 3600,
		PtrTtl:     3600,

		recordType:  dns.TypeA,
		ipSegments:  4,
		ipSeparator: ".",
		arpaSuffix:  ipv4ArpaSuffix,

		decodeIpSegments: ipv4Decode,
		encodeIp:         ipv4Encode,
		makeRec:          ipv4MakeRec,
		getPTRZones:      ipv4AddPTRZones,
	}
}
