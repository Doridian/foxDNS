package localizer_test

import (
	"net"
	"testing"

	"github.com/Doridian/foxDNS/handler/generator/localizer"
	"github.com/stretchr/testify/assert"
)

func TestIPNetAdd(t *testing.T) {
	subnet := net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.IPv4Mask(255, 255, 0, 0),
	}
	hostIP := net.IPv4(0, 0, 0, 3).To4()
	remoteIP := net.IPv4(10, 2, 3, 4).To4()

	assert.Equal(t, net.IPv4(10, 2, 0, 3).To4(), localizer.IPNetAdd(&subnet, hostIP, remoteIP))
}
