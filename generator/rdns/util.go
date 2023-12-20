package rdns

func NewRDNSGenerator(ipVersion int) *Generator {
	switch ipVersion {
	case 4:
		return NewIPv4()
	case 6:
		return NewIPv6()
	}
	return nil
}

func stringByteToByte(bs string) (byte, bool) {
	if len(bs) != 1 {
		return 0, false
	}
	b := []byte(bs)[0]

	if b >= 'A' && b <= 'F' {
		return (b - 'A') + 10, true
	}
	if b >= 'a' && b <= 'f' {
		return (b - 'a') + 10, true
	}
	if b >= '0' && b <= '9' {
		return (b - '0'), true
	}
	return 0, false
}

func twoStringByteToByte(lsbs string, msbs string) (byte, bool) {
	lsb, ok := stringByteToByte(lsbs)
	if !ok {
		return 0, false
	}
	msb, ok := stringByteToByte(msbs)
	if !ok {
		return 0, false
	}

	return lsb | (msb << 4), true
}
