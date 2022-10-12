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

func stringByteToByte(bs string) byte {
	b := []byte(bs)[0]

	if b >= 'A' && b <= 'F' {
		return (b - 'A') + 10
	}
	if b >= 'a' && b <= 'f' {
		return (b - 'a') + 10
	}
	if b >= '0' && b <= '9' {
		return (b - '0')
	}
	return 0
}

func twoStringByteToByte(lsbs string, msbs string) byte {
	lsb := stringByteToByte(lsbs)
	msb := stringByteToByte(msbs)

	return lsb | (msb << 4)
}
