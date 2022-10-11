package localizer

import "net"

func IPNetAdd(subnet *net.IPNet, hostIP net.IP, remoteIP net.IP) net.IP {
	mask := subnet.Mask
	n := len(hostIP)
	if n != len(mask) || n != len(remoteIP) {
		return nil
	}

	out := make(net.IP, n)
	for i := 0; i < n; i++ {
		out[i] = (hostIP[i] & ^mask[i]) | (remoteIP[i] & mask[i])
	}

	return out
}
