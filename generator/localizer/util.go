package localizer

import "net"

// IPNetAdd returns the result of adding the hostIP and remoteIP together, using the subnet as a mask.
// For example, assume:
// subnet = */16
// hostIP = 0.0.0.3
// remoteIP = 10.2.3.4
// This will yield the IP 10.2.0.3
func IPNetAdd(subnet *net.IPNet, hostIP net.IP, remoteIP net.IP) net.IP {
	mask := subnet.Mask
	n := len(hostIP)
	if n != len(remoteIP) {
		return nil
	}

	out := make(net.IP, n)
	for i := 0; i < n; i++ {
		out[i] = (hostIP[i] & ^mask[i]) | (remoteIP[i] & mask[i])
	}

	return out
}
